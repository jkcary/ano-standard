from __future__ import annotations

import copy
import hmac
import json
import math
import os
import re
import subprocess
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

from .errors import ANOError
from .schema import SchemaCatalog
from .util import canonical_json, new_id, parse_timestamp, sha256_json, utc_now


def sign_hmac_record(record: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Return a copy with a keyed integrity signature over every other field."""
    signed = copy.deepcopy(record)
    signed.pop("signature", None)
    digest = hmac.new(key, canonical_json(signed).encode("utf-8"), sha256).hexdigest()
    signed["signature"] = f"hmac-sha256:{digest}"
    return signed


def _verify_hmac_record(record: dict[str, Any], key: bytes, *, error_code: str) -> None:
    supplied = str(record.get("signature", ""))
    expected = sign_hmac_record(record, key)["signature"]
    if not hmac.compare_digest(supplied, expected):
        raise ANOError(error_code, "signed record integrity verification failed")


class ApprovalEvidenceVerifier:
    """Authenticates approval-service evidence and its expiry using trusted keyed issuers."""

    def __init__(self, catalog: SchemaCatalog, trusted_keys: dict[str, bytes]) -> None:
        self.catalog = catalog
        self._trusted_keys = dict(trusted_keys)

    def verify(self, evidence: dict[str, Any]) -> None:
        self.catalog.validate("structural-approval-evidence", evidence)
        key_id = str(evidence["key_id"])
        if key_id not in self._trusted_keys:
            raise ANOError("APPROVAL_ISSUER_UNTRUSTED", "approval evidence key is not trusted")
        _verify_hmac_record(evidence, self._trusted_keys[key_id], error_code="APPROVAL_SIGNATURE_INVALID")
        now = parse_timestamp(utc_now())
        issued_at, expires_at = parse_timestamp(str(evidence["issued_at"])), parse_timestamp(str(evidence["expires_at"]))
        if issued_at > now or expires_at <= issued_at:
            raise ANOError("APPROVAL_TIME_INVALID", "approval validity window is inconsistent")
        if expires_at <= now:
            raise ANOError("APPROVAL_EXPIRED", "structural approval has expired")
        approvals = evidence["approvals"]
        approver_ids = {item["approver_id"] for item in approvals}
        domains = {item["independence_domain"] for item in approvals}
        if len(approver_ids) != len(approvals) or len(domains) < 2 or evidence["proposer_domain"] in domains:
            raise ANOError("SEPARATION_VIOLATION", "verified approval actors and domains must be independent")


class IsolationAttestationVerifier:
    """Verifies that an independent issuer attested all mandatory isolation controls."""

    REQUIRED_CONTROLS = {
        "process_isolation": {"container", "virtual_machine", "dedicated_worker"},
        "network": {"none"},
        "filesystem": {"ephemeral_read_only_root"},
        "credentials": {"none"},
        "resource_limits": {True},
        "audit": {"complete"},
    }

    def __init__(self, catalog: SchemaCatalog, trusted_keys: dict[str, bytes]) -> None:
        self.catalog = catalog
        self._trusted_keys = dict(trusted_keys)

    def verify(self, attestation: dict[str, Any], *, artifact_hash: str, backend_id: str) -> None:
        self.catalog.validate("isolation-attestation", attestation)
        key_id = str(attestation["key_id"])
        if key_id not in self._trusted_keys:
            raise ANOError("ISOLATION_ISSUER_UNTRUSTED", "isolation attestation key is not trusted")
        _verify_hmac_record(attestation, self._trusted_keys[key_id], error_code="ISOLATION_SIGNATURE_INVALID")
        now = parse_timestamp(utc_now())
        issued_at = parse_timestamp(str(attestation["issued_at"]))
        expires_at = parse_timestamp(str(attestation["expires_at"]))
        if issued_at > now or expires_at <= issued_at:
            raise ANOError("ISOLATION_ATTESTATION_TIME_INVALID", "isolation validity window is inconsistent")
        if expires_at <= now:
            raise ANOError("ISOLATION_ATTESTATION_EXPIRED", "isolation attestation has expired")
        if attestation["artifact_hash"] != artifact_hash or attestation["backend_id"] != backend_id:
            raise ANOError("ISOLATION_BINDING_MISMATCH", "attestation does not bind this artifact and backend")
        controls = attestation["controls"]
        for name, allowed in self.REQUIRED_CONTROLS.items():
            if controls.get(name) not in allowed:
                raise ANOError("ISOLATION_CONTROL_MISSING", f"mandatory isolation control is not enforced: {name}")


class AttestedSandboxBackend(Protocol):
    backend_id: str

    def execute(self, request: dict[str, Any]) -> dict[str, Any]: ...


class AttestedSandboxRunner:
    """Runs candidates only after external isolation evidence passes verification."""

    def __init__(self, catalog: SchemaCatalog, verifier: IsolationAttestationVerifier) -> None:
        self.catalog = catalog
        self.verifier = verifier

    def run(
        self,
        *,
        backend: AttestedSandboxBackend,
        attestation: dict[str, Any],
        proposal_id: str,
        artifact: Any,
        inputs: dict[str, Any],
        allowed_inputs: set[str],
        allowed_outputs: set[str],
        limits: dict[str, Any],
    ) -> tuple[Any, dict[str, Any]]:
        artifact_hash = sha256_json(artifact)
        self.verifier.verify(attestation, artifact_hash=artifact_hash, backend_id=backend.backend_id)
        request = {
            "artifact": copy.deepcopy(artifact),
            "inputs": {key: copy.deepcopy(value) for key, value in inputs.items() if key in allowed_inputs},
            "allowed_outputs": sorted(allowed_outputs),
            "limits": copy.deepcopy(limits),
        }
        started_at = utc_now()
        result = backend.execute(request)
        output = copy.deepcopy(result.get("output"))
        denied = copy.deepcopy(result.get("denied_attempts", []))
        status = str(result.get("status", "passed"))
        if isinstance(output, dict) and not set(output) <= allowed_outputs:
            denied.append({"capability": "undeclared_output", "reason": "backend emitted undeclared output"})
            output, status = None, "blocked"
        if denied:
            output, status = None, "blocked"
        record = {
            "execution_id": new_id("sbx"), "schema_version": "0.3.0", "proposal_id": proposal_id,
            "artifact_hash": artifact_hash, "isolation_attestation_id": attestation["attestation_id"],
            "isolation_attestation_hash": sha256_json(attestation),
            "limits": copy.deepcopy(limits), "allowed_inputs": sorted(allowed_inputs),
            "allowed_outputs": sorted(allowed_outputs), "denied_attempts": denied,
            "resource_usage": copy.deepcopy(result.get("resource_usage", {})),
            "started_at": started_at, "finished_at": utc_now(), "status": status,
        }
        self.catalog.validate("sandbox-execution", record)
        return output, record


class DockerSandboxBackend:
    """Digest-pinned Docker adapter with a closed network and no host mounts."""

    _IMAGE = re.compile(r"^[a-zA-Z0-9._/-]+@sha256:[a-f0-9]{64}$")

    def __init__(
        self,
        image: str,
        command: list[str],
        *,
        backend_id: str = "docker_backend_001",
        docker_executable: str = "docker",
    ) -> None:
        if not self._IMAGE.fullmatch(image):
            raise ValueError("sandbox image must be pinned by sha256 digest")
        if not command:
            raise ValueError("sandbox command is required")
        self.image = image
        self.command = list(command)
        self.backend_id = backend_id
        self.docker_executable = docker_executable

    def command_for(self, limits: dict[str, Any]) -> list[str]:
        cpu_seconds = max(1, math.ceil(int(limits["cpu_ms"]) / 1000))
        return [
            self.docker_executable, "run", "--rm", "--interactive", "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534", "--pids-limit", "64",
            "--memory", f"{int(limits['memory_mb'])}m", "--cpus", "1",
            "--ulimit", f"cpu={cpu_seconds}:{cpu_seconds}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", self.image, *self.command,
        ]

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        limits = request["limits"]
        command = self.command_for(limits)
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command, input=canonical_json(request), text=True, capture_output=True,
                timeout=float(limits["wall_time_ms"]) / 1000, check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "output": None, "status": "timed_out", "denied_attempts": [],
                "resource_usage": {"wall_time_ms": float(limits["wall_time_ms"])},
            }
        except OSError as exc:
            raise ANOError("SANDBOX_BACKEND_UNAVAILABLE", "Docker sandbox backend is unavailable") from exc
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        if completed.returncode != 0:
            return {
                "output": None, "status": "failed",
                "denied_attempts": [{"capability": "sandbox_process", "reason": completed.stderr[-1024:] or "container failed"}],
                "resource_usage": {"wall_time_ms": elapsed_ms},
            }
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ANOError("SANDBOX_OUTPUT_INVALID", "container output must be one JSON object") from exc
        if not isinstance(response, dict):
            raise ANOError("SANDBOX_OUTPUT_INVALID", "container output must be one JSON object")
        return {
            "output": response.get("output"), "status": response.get("status", "passed"),
            "denied_attempts": response.get("denied_attempts", []),
            "resource_usage": {**response.get("resource_usage", {}), "wall_time_ms": elapsed_ms},
        }


class CanaryJournal:
    """Durable append-only canary checkpoints with sequence and hash-chain verification."""

    def __init__(self, path: str | Path, catalog: SchemaCatalog) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self._records: list[dict[str, Any]] = []
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        previous_hash: str | None = None
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ANOError("CANARY_JOURNAL_CORRUPT", f"invalid checkpoint JSON at line {line_number}") from exc
                self.catalog.validate("canary-checkpoint", record)
                material = copy.deepcopy(record)
                supplied_hash = material.pop("record_hash")
                if record["sequence"] != len(self._records) + 1 or record["previous_hash"] != previous_hash:
                    raise ANOError("CANARY_JOURNAL_CORRUPT", f"checkpoint sequence or predecessor mismatch at line {line_number}")
                if sha256_json(material) != supplied_hash:
                    raise ANOError("CANARY_JOURNAL_CORRUPT", f"checkpoint hash mismatch at line {line_number}")
                self._records.append(record)
                previous_hash = supplied_hash

    def append(self, event_type: str, snapshot: dict[str, Any]) -> dict[str, Any]:
        material = {
            "checkpoint_id": new_id("ckp"), "schema_version": "0.3.0",
            "sequence": len(self._records) + 1,
            "previous_hash": self._records[-1]["record_hash"] if self._records else None,
            "event_type": event_type, "occurred_at": utc_now(), "snapshot": copy.deepcopy(snapshot),
        }
        record = {**material, "record_hash": sha256_json(material)}
        self.catalog.validate("canary-checkpoint", record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._records.append(copy.deepcopy(record))
        return copy.deepcopy(record)

    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(self._records))

    def latest(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._records[-1]) if self._records else None
