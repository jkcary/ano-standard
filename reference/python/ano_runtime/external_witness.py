from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .control_plane import ClusterValidationEvidenceVerifier
from .errors import ANOError
from .evidence import (
    IndependentClusterEvidenceVerifier, WitnessedEvidenceLedger,
    create_cluster_evidence_envelope, dsse_pae,
)
from .schema import SchemaCatalog
from .util import sha256_json, utc_now


class DurableWitnessIssuer:
    """Witness-side signer with crash-safe monotonic state and last-request idempotency."""

    def __init__(
        self,
        path: str | Path,
        catalog: SchemaCatalog,
        private_key: Ed25519PrivateKey,
        *,
        key_id: str,
        runner_domain: str,
        witness_domain: str,
    ) -> None:
        if runner_domain == witness_domain:
            raise ANOError("WITNESS_INDEPENDENCE_VIOLATION", "runner and witness domains must differ")
        self.path = Path(path)
        self.catalog = catalog
        self.private_key = private_key
        self.key_id = key_id
        self.runner_domain = runner_domain
        self.witness_domain = witness_domain
        self._cluster_verifier = ClusterValidationEvidenceVerifier(catalog)
        self._self_verifier = IndependentClusterEvidenceVerifier(
            catalog, {key_id: (witness_domain, private_key.public_key())},
        )
        self._state = self._load_state() if self.path.exists() else None

    def _decode_last_statement(self, envelope: dict[str, Any]) -> dict[str, Any]:
        signature_entry = envelope["signatures"][0]
        try:
            payload = base64.b64decode(envelope["payload"], validate=True)
            signature = base64.b64decode(signature_entry["sig"], validate=True)
            self.private_key.public_key().verify(signature, dsse_pae(envelope["payloadType"], payload))
            statement = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, InvalidSignature) as exc:
            raise ANOError("WITNESS_STATE_CORRUPT", "last witness envelope is invalid") from exc
        self.catalog.validate("cluster-evidence-statement", statement)
        return statement

    def _load_state(self) -> dict[str, Any]:
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
            self.catalog.validate("witness-service-state", state)
        except (OSError, json.JSONDecodeError, ANOError) as exc:
            raise ANOError("WITNESS_STATE_CORRUPT", "witness state is unreadable or invalid") from exc
        if (
            state["key_id"] != self.key_id
            or state["runner_domain"] != self.runner_domain
            or state["witness_domain"] != self.witness_domain
        ):
            raise ANOError("WITNESS_STATE_BINDING_MISMATCH", "witness state belongs to another key or trust domain")
        if state["sequence"] != len(state["issued_runs"]):
            raise ANOError("WITNESS_STATE_CORRUPT", "witness sequence does not match issued run registry")
        previous_hash: str | None = None
        seen_runs: set[str] = set()
        for sequence, issued in enumerate(state["issued_runs"], start=1):
            envelope = issued["envelope"]
            if issued["run_id"] in seen_runs:
                raise ANOError("WITNESS_STATE_CORRUPT", "issued run registry contains a duplicate run")
            if envelope["signatures"][0]["keyid"] != self.key_id:
                raise ANOError("WITNESS_STATE_BINDING_MISMATCH", "issued envelope key identifier changed")
            envelope_hash = WitnessedEvidenceLedger.envelope_hash(envelope)
            if issued["envelope_hash"] != envelope_hash:
                raise ANOError("WITNESS_STATE_CORRUPT", "issued envelope hash does not match witness state")
            statement = self._decode_last_statement(envelope)
            if (
                statement["witness_sequence"] != sequence
                or statement["previous_envelope_hash"] != previous_hash
                or statement["subject"]["run_id"] != issued["run_id"]
                or statement["subject"]["report_hash"] != issued["report_hash"]
                or statement["runner_domain"] != self.runner_domain
                or statement["witness_domain"] != self.witness_domain
            ):
                raise ANOError("WITNESS_STATE_CORRUPT", "issued statement does not match witness state")
            seen_runs.add(issued["run_id"])
            previous_hash = envelope_hash
        last = state["issued_runs"][-1]
        if (
            last["run_id"] != state["last_run_id"]
            or last["report_hash"] != state["last_report_hash"]
            or last["envelope_hash"] != state["last_envelope_hash"]
            or last["envelope"] != state["last_envelope"]
        ):
            raise ANOError("WITNESS_STATE_CORRUPT", "last witness fields do not match issued run registry")
        return state

    def _persist_state(self, state: dict[str, Any]) -> None:
        self.catalog.validate("witness-service-state", state)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(state, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(self.path)

    def issue(self, report: dict[str, Any]) -> dict[str, Any]:
        self._cluster_verifier.verify(report)
        report_hash = sha256_json(report)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ANOError("WITNESS_CONCURRENT_WRITE", "witness state writer lock is already held") from exc
        try:
            os.write(lock_fd, str(os.getpid()).encode("ascii"))
            os.fsync(lock_fd)
            disk_state = self._load_state() if self.path.exists() else None
            existing = None if disk_state is None else next(
                (item for item in disk_state["issued_runs"] if item["run_id"] == report["run_id"]), None,
            )
            if existing is not None:
                if existing["report_hash"] != report_hash:
                    raise ANOError("WITNESS_RUN_REBIND", "run identifier is already bound to different report bytes")
                self._state = disk_state
                return copy.deepcopy(existing["envelope"])
            sequence = 1 if disk_state is None else int(disk_state["sequence"]) + 1
            previous_hash = None if disk_state is None else str(disk_state["last_envelope_hash"])
            envelope = create_cluster_evidence_envelope(
                report, self.private_key, key_id=self.key_id,
                runner_domain=self.runner_domain, witness_domain=self.witness_domain,
                witness_sequence=sequence, previous_envelope_hash=previous_hash,
            )
            self._self_verifier.verify(
                report, envelope, expected_sequence=sequence,
                expected_previous_envelope_hash=previous_hash,
            )
            issued = {
                "run_id": report["run_id"], "report_hash": report_hash,
                "envelope_hash": WitnessedEvidenceLedger.envelope_hash(envelope),
                "envelope": envelope,
            }
            state = {
                "schema_version": "0.3.0", "key_id": self.key_id,
                "runner_domain": self.runner_domain, "witness_domain": self.witness_domain,
                "sequence": sequence, "last_run_id": report["run_id"],
                "last_report_hash": report_hash,
                "issued_runs": ([] if disk_state is None else copy.deepcopy(disk_state["issued_runs"])) + [issued],
                "last_envelope_hash": issued["envelope_hash"],
                "last_envelope": envelope, "updated_at": utc_now(),
            }
            self._persist_state(state)
            self._state = state
            return copy.deepcopy(envelope)
        finally:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)

    def status(self) -> dict[str, Any]:
        state = self._load_state() if self.path.exists() else None
        return {
            "key_id": self.key_id, "witness_domain": self.witness_domain,
            "sequence": 0 if state is None else state["sequence"],
            "last_envelope_hash": None if state is None else state["last_envelope_hash"],
        }
