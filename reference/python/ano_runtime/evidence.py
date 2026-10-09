from __future__ import annotations

import base64
import copy
import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .control_plane import ClusterValidationEvidenceVerifier
from .errors import ANOError
from .schema import SchemaCatalog
from .util import canonical_json, new_id, parse_timestamp, sha256_json, utc_now


CLUSTER_EVIDENCE_PAYLOAD_TYPE = "application/vnd.ano.cluster-evidence-statement.v1+json"


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding for type-bound signatures."""
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(type_bytes)).encode("ascii") + b" " + type_bytes + b" " + str(len(payload)).encode("ascii") + b" " + payload


def create_cluster_evidence_envelope(
    report: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    runner_domain: str,
    witness_domain: str,
    witness_sequence: int,
    previous_envelope_hash: str | None,
    witnessed_at: str | None = None,
    observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Witness-side helper; production runners must not hold this private key."""
    statement = {
        "statement_id": new_id("wit"), "schema_version": "0.3.0",
        "predicate_type": "urn:ano:predicate:cluster-validation:v1",
        "subject": {"run_id": report["run_id"], "report_hash": sha256_json(report)},
        "runner_domain": runner_domain, "witness_domain": witness_domain,
        "witnessed_at": witnessed_at or utc_now(), "witness_sequence": witness_sequence,
        "previous_envelope_hash": previous_envelope_hash,
        "witness_policy": "independent-domain-v1",
    }
    if observation is not None:
        statement["observation"] = copy.deepcopy(observation)
    payload = canonical_json(statement).encode("utf-8")
    signature = private_key.sign(dsse_pae(CLUSTER_EVIDENCE_PAYLOAD_TYPE, payload))
    return {
        "payloadType": CLUSTER_EVIDENCE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}],
    }


class IndependentClusterEvidenceVerifier:
    """Verifies a type-bound report attestation from an independent trust domain."""

    def __init__(
        self,
        catalog: SchemaCatalog,
        trusted_witnesses: dict[str, tuple[str, Ed25519PublicKey]],
        *,
        maximum_future_skew_seconds: int = 60,
    ) -> None:
        self.catalog = catalog
        self._trusted_witnesses = dict(trusted_witnesses)
        self._future_skew = timedelta(seconds=maximum_future_skew_seconds)
        self._cluster_verifier = ClusterValidationEvidenceVerifier(catalog)

    def verify(
        self,
        report: dict[str, Any],
        envelope: dict[str, Any],
        *,
        expected_sequence: int,
        expected_previous_envelope_hash: str | None,
    ) -> dict[str, Any]:
        self.catalog.validate("cluster-evidence-envelope", envelope)
        signature_entry = envelope["signatures"][0]
        key_id = str(signature_entry["keyid"])
        trusted = self._trusted_witnesses.get(key_id)
        if trusted is None:
            raise ANOError("WITNESS_UNTRUSTED", "evidence witness key is not trusted")
        try:
            payload = base64.b64decode(envelope["payload"], validate=True)
            signature = base64.b64decode(signature_entry["sig"], validate=True)
            trusted[1].verify(signature, dsse_pae(envelope["payloadType"], payload))
        except (ValueError, InvalidSignature) as exc:
            raise ANOError("WITNESS_SIGNATURE_INVALID", "evidence witness signature is invalid") from exc
        try:
            statement = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ANOError("WITNESS_PAYLOAD_INVALID", "signed witness payload is not valid UTF-8 JSON") from exc
        self.catalog.validate("cluster-evidence-statement", statement)
        self._cluster_verifier.verify(report)
        if statement["witness_domain"] != trusted[0]:
            raise ANOError("WITNESS_IDENTITY_MISMATCH", "signed witness domain does not match trusted key policy")
        if statement["runner_domain"] == statement["witness_domain"]:
            raise ANOError("WITNESS_INDEPENDENCE_VIOLATION", "runner and witness must be in different trust domains")
        subject = statement["subject"]
        if subject["run_id"] != report["run_id"] or subject["report_hash"] != sha256_json(report):
            raise ANOError("EVIDENCE_SUBJECT_MISMATCH", "witness statement does not bind this cluster report")
        witnessed_at = parse_timestamp(statement["witnessed_at"])
        if witnessed_at < parse_timestamp(report["finished_at"]):
            raise ANOError("WITNESS_TIME_INVALID", "report was witnessed before the experiment finished")
        if witnessed_at > parse_timestamp(utc_now()) + self._future_skew:
            raise ANOError("WITNESS_TIME_INVALID", "witness timestamp is too far in the future")
        if statement["witness_sequence"] != expected_sequence:
            raise ANOError("WITNESS_REPLAY_OR_GAP", "witness sequence is not continuous")
        if statement["previous_envelope_hash"] != expected_previous_envelope_hash:
            raise ANOError("WITNESS_REPLAY_OR_GAP", "witness predecessor does not match the accepted chain")
        return copy.deepcopy(statement)


class WitnessedEvidenceLedger:
    """Durable evidence archive with witness-chain and local hash-chain verification."""

    def __init__(self, path: str | Path, catalog: SchemaCatalog, verifier: IndependentClusterEvidenceVerifier) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.verifier = verifier
        self._records = self._read_and_verify() if self.path.exists() else []

    @staticmethod
    def envelope_hash(envelope: dict[str, Any]) -> str:
        return sha256_json(envelope)

    @staticmethod
    def _record_hash(record: dict[str, Any]) -> str:
        material = copy.deepcopy(record)
        material.pop("record_hash", None)
        return sha256_json(material)

    def _read_and_verify(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        previous_record_hash: str | None = None
        previous_envelope_hash: str | None = None
        seen_runs: set[str] = set()
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    self.catalog.validate("evidence-ledger-record", record)
                    expected_sequence = len(records) + 1
                    if record["sequence"] != expected_sequence or record["previous_hash"] != previous_record_hash:
                        raise ValueError(f"record sequence or predecessor mismatch at line {line_number}")
                    if record["record_hash"] != self._record_hash(record):
                        raise ValueError(f"record hash mismatch at line {line_number}")
                    envelope_hash = self.envelope_hash(record["envelope"])
                    if record["envelope_hash"] != envelope_hash:
                        raise ValueError(f"envelope hash mismatch at line {line_number}")
                    run_id = str(record["report"]["run_id"])
                    if run_id in seen_runs:
                        raise ValueError(f"duplicate run id at line {line_number}")
                    self.verifier.verify(
                        record["report"], record["envelope"], expected_sequence=expected_sequence,
                        expected_previous_envelope_hash=previous_envelope_hash,
                    )
                    records.append(record)
                    seen_runs.add(run_id)
                    previous_record_hash = record["record_hash"]
                    previous_envelope_hash = envelope_hash
        except (OSError, json.JSONDecodeError, ValueError, ANOError) as exc:
            raise ANOError("EVIDENCE_LEDGER_CORRUPT", "evidence ledger integrity verification failed") from exc
        return records

    def append(self, report: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ANOError("EVIDENCE_LEDGER_CONCURRENT_WRITE", "evidence ledger writer lock is already held") from exc
        try:
            os.write(lock_fd, str(os.getpid()).encode("ascii"))
            os.fsync(lock_fd)
            disk_records = self._read_and_verify() if self.path.exists() else []
            if [item["record_hash"] for item in disk_records] != [item["record_hash"] for item in self._records]:
                raise ANOError("EVIDENCE_LEDGER_CONCURRENT_WRITE", "evidence ledger changed since it was opened")
            if any(item["report"]["run_id"] == report["run_id"] for item in self._records):
                raise ANOError("EVIDENCE_REPLAY", "cluster run is already present in the evidence ledger")
            sequence = len(self._records) + 1
            previous_envelope_hash = self.envelope_hash(self._records[-1]["envelope"]) if self._records else None
            self.verifier.verify(
                report, envelope, expected_sequence=sequence,
                expected_previous_envelope_hash=previous_envelope_hash,
            )
            material = {
                "record_id": new_id("eld"), "schema_version": "0.3.0", "sequence": sequence,
                "previous_hash": self._records[-1]["record_hash"] if self._records else None,
                "envelope_hash": self.envelope_hash(envelope), "appended_at": utc_now(),
                "report": copy.deepcopy(report), "envelope": copy.deepcopy(envelope),
            }
            record = {**material, "record_hash": self._record_hash(material)}
            self.catalog.validate("evidence-ledger-record", record)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._records.append(copy.deepcopy(record))
            return copy.deepcopy(record)
        finally:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)

    def verify(self, *, expected_head_hash: str | None = None) -> None:
        records = self._read_and_verify() if self.path.exists() else []
        head = records[-1]["record_hash"] if records else None
        if expected_head_hash is not None and head != expected_head_hash:
            raise ANOError("EVIDENCE_LEDGER_TRUNCATED", "evidence ledger head does not match the external anchor")
        self._records = records

    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(self._records))

    def head_hash(self) -> str | None:
        return self._records[-1]["record_hash"] if self._records else None
