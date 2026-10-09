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
from .evidence import dsse_pae
from .quorum import IndependentWitnessQuorumVerifier
from .schema import SchemaCatalog
from .util import canonical_json, new_id, parse_timestamp, sha256_json, utc_now
from .witness_policy import witness_public_key_fingerprint


CLUSTER_REPORT_SOURCE_PAYLOAD_TYPE = "application/vnd.ano.cluster-report-source-statement.v1+json"
SOURCE_TRANSPARENCY_CHECKPOINT_PAYLOAD_TYPE = "application/vnd.ano.source-transparency-checkpoint.v1+json"


def create_cluster_report_source_envelope(
    report: dict[str, Any], private_key: Ed25519PrivateKey, *, key_id: str,
    source_id: str, source_domain: str, issued_at: str | None = None,
) -> dict[str, Any]:
    statement = {
        "statement_id": new_id("src"), "schema_version": "0.3.0",
        "predicate_type": "urn:ano:predicate:cluster-report-source:v1",
        "subject": {"run_id": report["run_id"], "report_hash": sha256_json(report)},
        "source_id": source_id, "source_domain": source_domain,
        "issued_at": issued_at or utc_now(),
    }
    payload = canonical_json(statement).encode("utf-8")
    signature = private_key.sign(dsse_pae(CLUSTER_REPORT_SOURCE_PAYLOAD_TYPE, payload))
    return {
        "payloadType": CLUSTER_REPORT_SOURCE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}],
    }


def create_source_transparency_checkpoint(
    *, registry_id: str, log_id: str, sequence: int, head_hash: str,
    private_key: Ed25519PrivateKey, key_id: str, issued_at: str | None = None,
) -> dict[str, Any]:
    """Sign an externally gossipable commitment to one registry prefix."""
    statement = {
        "checkpoint_id": new_id("tcp"), "schema_version": "0.3.0",
        "registry_id": registry_id, "log_id": log_id, "sequence": sequence,
        "head_hash": head_hash, "issued_at": issued_at or utc_now(),
    }
    payload = canonical_json(statement).encode("utf-8")
    signature = private_key.sign(dsse_pae(SOURCE_TRANSPARENCY_CHECKPOINT_PAYLOAD_TYPE, payload))
    return {
        "payloadType": SOURCE_TRANSPARENCY_CHECKPOINT_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}],
    }


class PolicyBoundTransparencyCheckpointVerifier:
    """Verify signed registry checkpoints against a pinned log-key lifecycle policy."""

    def __init__(
        self, catalog: SchemaCatalog, policy: dict[str, Any],
        trusted_public_keys: dict[str, Ed25519PublicKey], *, expected_policy_id: str,
        minimum_policy_version: int, expected_policy_hash: str,
        maximum_future_skew_seconds: int = 60,
    ) -> None:
        trusted_policy = copy.deepcopy(policy)
        catalog.validate("transparency-log-policy", trusted_policy)
        if trusted_policy["policy_id"] != expected_policy_id:
            raise ANOError("TRANSPARENCY_POLICY_IDENTITY", "transparency policy identity does not match its trust root")
        if trusted_policy["policy_version"] < minimum_policy_version:
            raise ANOError("TRANSPARENCY_POLICY_ROLLBACK", "transparency policy version is older than its configured floor")
        if sha256_json(trusted_policy) != expected_policy_hash:
            raise ANOError("TRANSPARENCY_POLICY_INTEGRITY", "transparency policy does not match its integrity anchor")
        entries: dict[str, dict[str, Any]] = {}
        log_claims: dict[str, tuple[str, str]] = {}
        policy_issued_at = parse_timestamp(trusted_policy["issued_at"])
        for entry in trusted_policy["logs"]:
            key_id = str(entry["key_id"])
            if key_id in entries:
                raise ANOError("TRANSPARENCY_POLICY_INVALID", "transparency policy contains a duplicate key identifier")
            key = trusted_public_keys.get(key_id)
            if key is None:
                raise ANOError("TRANSPARENCY_KEY_MISSING", "transparency policy references an unavailable public key")
            if witness_public_key_fingerprint(key) != entry["public_key_sha256"]:
                raise ANOError("TRANSPARENCY_KEY_FINGERPRINT_MISMATCH", "transparency key fingerprint does not match policy")
            valid_from, valid_until = parse_timestamp(entry["valid_from"]), parse_timestamp(entry["valid_until"])
            if valid_from >= valid_until:
                raise ANOError("TRANSPARENCY_POLICY_INVALID", "transparency key validity interval is invalid")
            revoked_at = None if entry["revoked_at"] is None else parse_timestamp(entry["revoked_at"])
            if entry["status"] == "revoked":
                if revoked_at is None or entry["revocation_mode"] == "none":
                    raise ANOError("TRANSPARENCY_POLICY_INVALID", "revoked transparency key has no effective revocation")
                if not (valid_from <= revoked_at < valid_until) or revoked_at > policy_issued_at:
                    raise ANOError("TRANSPARENCY_POLICY_INVALID", "transparency key revocation time is invalid")
            elif revoked_at is not None or entry["revocation_mode"] != "none":
                raise ANOError("TRANSPARENCY_POLICY_INVALID", "non-revoked transparency key declares revocation")
            if entry["status"] == "active" and not (valid_from <= policy_issued_at < valid_until):
                raise ANOError("TRANSPARENCY_POLICY_INVALID", "active transparency key is not valid at policy issuance")
            if entry["status"] == "retired" and valid_until > policy_issued_at:
                raise ANOError("TRANSPARENCY_POLICY_INVALID", "retired transparency key has a future validity end")
            claims = (str(entry["registry_id"]), str(entry["operator_domain"]))
            previous_claims = log_claims.get(str(entry["log_id"]))
            if previous_claims is not None and previous_claims != claims:
                raise ANOError("TRANSPARENCY_POLICY_INVALID", "rotated keys changed the transparency log identity")
            log_claims[str(entry["log_id"])] = claims
            entries[key_id] = entry
        if set(trusted_public_keys) != set(entries):
            raise ANOError("TRANSPARENCY_POLICY_INVALID", "trusted transparency key set differs from policy")
        self._catalog = catalog
        self._entries = entries
        self._keys = dict(trusted_public_keys)
        self._future_skew = timedelta(seconds=maximum_future_skew_seconds)

    def verify(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self._catalog.validate("source-transparency-checkpoint-envelope", envelope)
        signature_entry = envelope["signatures"][0]
        key_id = str(signature_entry["keyid"])
        entry = self._entries.get(key_id)
        if entry is None:
            raise ANOError("TRANSPARENCY_LOG_UNTRUSTED", "checkpoint signing key is not trusted")
        try:
            payload = base64.b64decode(envelope["payload"], validate=True)
            signature = base64.b64decode(signature_entry["sig"], validate=True)
            self._keys[key_id].verify(signature, dsse_pae(envelope["payloadType"], payload))
            statement = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, InvalidSignature) as exc:
            raise ANOError("TRANSPARENCY_CHECKPOINT_SIGNATURE_INVALID", "checkpoint signature is invalid") from exc
        self._catalog.validate("source-transparency-checkpoint", statement)
        if statement["log_id"] != entry["log_id"] or statement["registry_id"] != entry["registry_id"]:
            raise ANOError("TRANSPARENCY_LOG_IDENTITY_MISMATCH", "checkpoint identity differs from policy")
        issued_at = parse_timestamp(statement["issued_at"])
        if issued_at > parse_timestamp(utc_now()) + self._future_skew:
            raise ANOError("TRANSPARENCY_CHECKPOINT_TIME_INVALID", "checkpoint is issued in the future")
        if not (parse_timestamp(entry["valid_from"]) <= issued_at < parse_timestamp(entry["valid_until"])):
            raise ANOError("TRANSPARENCY_KEY_OUTSIDE_VALIDITY", "checkpoint is outside key validity")
        if entry["status"] == "revoked":
            revoked_at = parse_timestamp(entry["revoked_at"])
            if entry["revocation_mode"] == "retroactive" or issued_at >= revoked_at:
                raise ANOError("TRANSPARENCY_KEY_REVOKED", "checkpoint signing key is revoked")
        return copy.deepcopy(statement)


class PolicyBoundClusterReportSourceVerifier:
    """Verify source-signed reports against an anchored source-key lifecycle policy."""

    def __init__(
        self, catalog: SchemaCatalog, policy: dict[str, Any],
        trusted_public_keys: dict[str, Ed25519PublicKey], *,
        expected_policy_id: str, minimum_policy_version: int, expected_policy_hash: str,
        maximum_future_skew_seconds: int = 60,
    ) -> None:
        trusted_policy = copy.deepcopy(policy)
        catalog.validate("observation-source-policy", trusted_policy)
        if trusted_policy["policy_id"] != expected_policy_id:
            raise ANOError("OBSERVATION_SOURCE_POLICY_IDENTITY", "source policy identity does not match its trust root")
        if trusted_policy["policy_version"] < minimum_policy_version:
            raise ANOError("OBSERVATION_SOURCE_POLICY_ROLLBACK", "source policy version is older than its configured floor")
        if sha256_json(trusted_policy) != expected_policy_hash:
            raise ANOError("OBSERVATION_SOURCE_POLICY_INTEGRITY", "source policy does not match its integrity anchor")
        policy_issued_at = parse_timestamp(trusted_policy["issued_at"])
        entries: dict[str, dict[str, Any]] = {}
        source_claims: dict[str, tuple[Any, ...]] = {}
        for entry in trusted_policy["sources"]:
            key_id = str(entry["key_id"])
            if key_id in entries:
                raise ANOError("OBSERVATION_SOURCE_POLICY_INVALID", "source policy contains a duplicate key identifier")
            valid_from, valid_until = parse_timestamp(entry["valid_from"]), parse_timestamp(entry["valid_until"])
            if valid_from >= valid_until:
                raise ANOError("OBSERVATION_SOURCE_POLICY_INVALID", "source key validity interval is invalid")
            revoked_at = None if entry["revoked_at"] is None else parse_timestamp(entry["revoked_at"])
            if revoked_at is not None and not (valid_from <= revoked_at < valid_until):
                raise ANOError("OBSERVATION_SOURCE_POLICY_INVALID", "source revocation is outside key validity")
            if entry["status"] == "active" and not (valid_from <= policy_issued_at < valid_until):
                raise ANOError("OBSERVATION_SOURCE_POLICY_INVALID", "active source key is not valid at policy issuance")
            if entry["status"] == "retired" and valid_until > policy_issued_at:
                raise ANOError("OBSERVATION_SOURCE_POLICY_INVALID", "retired source key has a future validity end")
            if entry["status"] == "revoked" and revoked_at is not None and revoked_at > policy_issued_at:
                raise ANOError("OBSERVATION_SOURCE_POLICY_INVALID", "source is marked revoked before revocation time")
            key = trusted_public_keys.get(key_id)
            if key is None:
                raise ANOError("OBSERVATION_SOURCE_KEY_MISSING", "source policy references an unavailable public key")
            if witness_public_key_fingerprint(key) != entry["public_key_sha256"]:
                raise ANOError("OBSERVATION_SOURCE_KEY_FINGERPRINT_MISMATCH", "source key fingerprint does not match policy")
            claims = (
                entry["source_domain"], entry["operator_domain"], entry["infrastructure_domain"],
                tuple(sorted(entry["upstream_ids"])),
            )
            existing_claims = source_claims.get(str(entry["source_id"]))
            if existing_claims is not None and existing_claims != claims:
                raise ANOError("OBSERVATION_SOURCE_POLICY_INVALID", "rotated keys changed the source independence identity")
            source_claims[str(entry["source_id"])] = claims
            entries[key_id] = entry
        if set(trusted_public_keys) != set(entries):
            raise ANOError("OBSERVATION_SOURCE_POLICY_INVALID", "trusted source key set differs from policy")
        self._catalog = catalog
        self._entries = entries
        self._keys = dict(trusted_public_keys)
        self._cluster_verifier = ClusterValidationEvidenceVerifier(catalog)
        self._future_skew = timedelta(seconds=maximum_future_skew_seconds)
        self.maximum_source_age_seconds = int(trusted_policy["maximum_source_age_seconds"])

    def verify(self, report: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
        self._catalog.validate("cluster-report-source-envelope", envelope)
        signature_entry = envelope["signatures"][0]
        key_id = str(signature_entry["keyid"])
        entry = self._entries.get(key_id)
        if entry is None:
            raise ANOError("OBSERVATION_SOURCE_UNTRUSTED", "source signing key is not trusted")
        try:
            payload = base64.b64decode(envelope["payload"], validate=True)
            signature = base64.b64decode(signature_entry["sig"], validate=True)
            self._keys[key_id].verify(signature, dsse_pae(envelope["payloadType"], payload))
            statement = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, InvalidSignature) as exc:
            raise ANOError("OBSERVATION_SOURCE_SIGNATURE_INVALID", "source report signature is invalid") from exc
        self._catalog.validate("cluster-report-source-statement", statement)
        self._cluster_verifier.verify(report)
        if statement["source_id"] != entry["source_id"] or statement["source_domain"] != entry["source_domain"]:
            raise ANOError("OBSERVATION_SOURCE_IDENTITY_MISMATCH", "source statement identity differs from policy")
        if statement["subject"]["run_id"] != report["run_id"] or statement["subject"]["report_hash"] != sha256_json(report):
            raise ANOError("OBSERVATION_SOURCE_SUBJECT_MISMATCH", "source statement does not bind this report")
        issued_at = parse_timestamp(statement["issued_at"])
        if issued_at < parse_timestamp(report["finished_at"]) or issued_at > parse_timestamp(utc_now()) + self._future_skew:
            raise ANOError("OBSERVATION_SOURCE_TIME_INVALID", "source statement time is invalid")
        if not (parse_timestamp(entry["valid_from"]) <= issued_at < parse_timestamp(entry["valid_until"])):
            raise ANOError("OBSERVATION_SOURCE_KEY_OUTSIDE_VALIDITY", "source statement is outside key validity")
        if entry["status"] == "revoked":
            if entry["revocation_mode"] == "retroactive" or issued_at >= parse_timestamp(entry["revoked_at"]):
                raise ANOError("OBSERVATION_SOURCE_KEY_REVOKED", "source signing key is revoked for this statement")
        return copy.deepcopy(statement)

    def verify_collected(
        self, report: dict[str, Any], envelope: dict[str, Any], *, collected_at: str,
    ) -> dict[str, Any]:
        statement = self.verify(report, envelope)
        collected = parse_timestamp(collected_at)
        issued = parse_timestamp(statement["issued_at"])
        if collected < issued:
            raise ANOError("OBSERVATION_TIME_INVALID", "observation predates the signed source statement")
        if collected - issued > timedelta(seconds=self.maximum_source_age_seconds):
            raise ANOError("OBSERVATION_SOURCE_STALE", "source statement is older than the observation policy allows")
        return statement

    def policy_entry(self, key_id: str) -> dict[str, Any]:
        entry = self._entries.get(key_id)
        if entry is None:
            raise ANOError("OBSERVATION_SOURCE_UNTRUSTED", "source signing key is not trusted")
        return copy.deepcopy(entry)


class IndependentObservationQuorumVerifier:
    """Require each witness vote to carry a separately verifiable, independent source lineage."""

    def __init__(
        self, catalog: SchemaCatalog, quorum_verifier: IndependentWitnessQuorumVerifier,
        source_verifier: PolicyBoundClusterReportSourceVerifier,
    ) -> None:
        self._catalog = catalog
        self._quorum_verifier = quorum_verifier
        self._source_verifier = source_verifier

    def verify(
        self, report: dict[str, Any], bundle: dict[str, Any], *,
        chain_heads: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        verified = self._quorum_verifier.verify(report, bundle, chain_heads=chain_heads)
        attestations = bundle.get("source_attestations")
        if not isinstance(attestations, list):
            raise ANOError("OBSERVATION_LINEAGE_MISSING", "observation quorum requires source attestations")
        by_observer: dict[str, dict[str, Any]] = {}
        for item in attestations:
            observer_key_id = str(item["observer_key_id"])
            if observer_key_id in by_observer:
                raise ANOError("OBSERVATION_LINEAGE_DUPLICATE", "observer has multiple source attestations")
            by_observer[observer_key_id] = item["source_envelope"]
        expected_keys = set(verified["member_key_ids"].values())
        if set(by_observer) != expected_keys:
            raise ANOError("OBSERVATION_LINEAGE_MISMATCH", "source attestations do not exactly cover quorum observers")
        source_domains: set[str] = set()
        operator_domains: set[str] = set()
        infrastructure_domains: set[str] = set()
        upstream_ids: set[str] = set()
        source_statements: dict[str, dict[str, Any]] = {}
        for member_id, observer_key_id in verified["member_key_ids"].items():
            witness_statement = verified["statements"][member_id]
            observation = witness_statement.get("observation")
            if not isinstance(observation, dict):
                raise ANOError("OBSERVATION_LINEAGE_MISSING", "witness statement has no signed observation lineage")
            source_envelope = by_observer[observer_key_id]
            source_statement = self._source_verifier.verify_collected(
                report, source_envelope, collected_at=observation["collected_at"],
            )
            if (
                observation["source_id"] != source_statement["source_id"]
                or observation["source_domain"] != source_statement["source_domain"]
                or observation["source_key_id"] != source_envelope["signatures"][0]["keyid"]
                or observation["source_envelope_hash"] != sha256_json(source_envelope)
            ):
                raise ANOError("OBSERVATION_LINEAGE_MISMATCH", "signed observation does not bind its source attestation")
            source_domain = str(source_statement["source_domain"])
            if source_domain in source_domains:
                raise ANOError("OBSERVATION_SOURCE_DOMAIN_DUPLICATE", "independent observation votes must use distinct source domains")
            source_entry = self._source_verifier.policy_entry(str(source_envelope["signatures"][0]["keyid"]))
            operator_domain = str(source_entry["operator_domain"])
            infrastructure_domain = str(source_entry["infrastructure_domain"])
            source_upstreams = set(str(item) for item in source_entry["upstream_ids"])
            if operator_domain in operator_domains:
                raise ANOError("OBSERVATION_COMMON_OPERATOR", "observation sources share an operator control domain")
            if infrastructure_domain in infrastructure_domains:
                raise ANOError("OBSERVATION_COMMON_INFRASTRUCTURE", "observation sources share an infrastructure failure domain")
            if source_upstreams & upstream_ids:
                raise ANOError("OBSERVATION_COMMON_UPSTREAM", "observation sources share an upstream evidence root")
            if source_domain in {witness_statement["witness_domain"], witness_statement["runner_domain"]}:
                raise ANOError("OBSERVATION_INDEPENDENCE_VIOLATION", "source, observer and runner must use independent trust domains")
            collected_at = parse_timestamp(observation["collected_at"])
            if collected_at > parse_timestamp(witness_statement["witnessed_at"]):
                raise ANOError("OBSERVATION_TIME_INVALID", "observation collection time is outside its signed lineage")
            source_domains.add(source_domain)
            operator_domains.add(operator_domain)
            infrastructure_domains.add(infrastructure_domain)
            upstream_ids.update(source_upstreams)
            source_statements[member_id] = source_statement
        return {
            **verified, "source_domains": sorted(source_domains),
            "operator_domains": sorted(operator_domains),
            "infrastructure_domains": sorted(infrastructure_domains),
            "upstream_ids": sorted(upstream_ids), "source_statements": source_statements,
        }


class SourceObservationRegistry:
    """Durably preserve source publications and detect same-run signed equivocation."""

    def __init__(
        self, path: str | Path, catalog: SchemaCatalog,
        source_verifier: PolicyBoundClusterReportSourceVerifier,
    ) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.source_verifier = source_verifier
        self._records = self._read_and_verify() if self.path.exists() else []

    @staticmethod
    def _record_hash(record: dict[str, Any]) -> str:
        material = copy.deepcopy(record)
        material.pop("record_hash", None)
        return sha256_json(material)

    def _read_and_verify(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        previous_hash: str | None = None
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    self.catalog.validate("source-observation-registry-record", record)
                    if record["sequence"] != len(records) + 1 or record["previous_hash"] != previous_hash:
                        raise ValueError(f"source registry sequence mismatch at line {line_number}")
                    if record["record_hash"] != self._record_hash(record):
                        raise ValueError(f"source registry hash mismatch at line {line_number}")
                    statement = self.source_verifier.verify(record["report"], record["source_envelope"])
                    if (
                        record["source_id"] != statement["source_id"]
                        or record["source_domain"] != statement["source_domain"]
                        or record["run_id"] != record["report"]["run_id"]
                        or record["report_hash"] != sha256_json(record["report"])
                        or record["source_envelope_hash"] != sha256_json(record["source_envelope"])
                    ):
                        raise ValueError(f"source registry binding mismatch at line {line_number}")
                    conflict = next((
                        item for item in records
                        if item["source_id"] == record["source_id"]
                        and item["run_id"] == record["run_id"]
                        and item["report_hash"] != record["report_hash"]
                    ), None)
                    expected_verdict = "equivocation" if conflict is not None else "accepted"
                    expected_conflict = None if conflict is None else conflict["record_id"]
                    if record["verdict"] != expected_verdict or record["conflicts_with_record_id"] != expected_conflict:
                        raise ValueError(f"source registry equivocation verdict mismatch at line {line_number}")
                    records.append(record)
                    previous_hash = record["record_hash"]
        except (OSError, json.JSONDecodeError, ValueError, ANOError) as exc:
            raise ANOError("SOURCE_REGISTRY_CORRUPT", "source observation registry integrity verification failed") from exc
        return records

    def append(self, report: dict[str, Any], source_envelope: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ANOError("SOURCE_REGISTRY_CONCURRENT_WRITE", "source registry writer lock is already held") from exc
        try:
            os.write(lock_fd, str(os.getpid()).encode("ascii"))
            os.fsync(lock_fd)
            disk_records = self._read_and_verify() if self.path.exists() else []
            if [item["record_hash"] for item in disk_records] != [item["record_hash"] for item in self._records]:
                raise ANOError("SOURCE_REGISTRY_CONCURRENT_WRITE", "source registry changed since it was opened")
            statement = self.source_verifier.verify(report, source_envelope)
            envelope_hash = sha256_json(source_envelope)
            identical = next((item for item in self._records if item["source_envelope_hash"] == envelope_hash), None)
            if identical is not None:
                return copy.deepcopy(identical)
            report_hash = sha256_json(report)
            conflict = next((
                item for item in self._records
                if item["source_id"] == statement["source_id"]
                and item["run_id"] == report["run_id"]
                and item["report_hash"] != report_hash
            ), None)
            material = {
                "record_id": new_id("sor"), "schema_version": "0.3.0",
                "sequence": len(self._records) + 1,
                "previous_hash": self._records[-1]["record_hash"] if self._records else None,
                "source_id": statement["source_id"], "source_domain": statement["source_domain"],
                "run_id": report["run_id"], "report_hash": report_hash,
                "source_envelope_hash": envelope_hash, "observed_at": utc_now(),
                "verdict": "equivocation" if conflict is not None else "accepted",
                "conflicts_with_record_id": None if conflict is None else conflict["record_id"],
                "report": copy.deepcopy(report), "source_envelope": copy.deepcopy(source_envelope),
            }
            record = {**material, "record_hash": self._record_hash(material)}
            self.catalog.validate("source-observation-registry-record", record)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._records.append(copy.deepcopy(record))
            if conflict is not None:
                raise ANOError("SOURCE_EQUIVOCATION_DETECTED", "source signed different reports for the same run")
            return copy.deepcopy(record)
        finally:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)

    def verify(self, *, expected_head_hash: str | None = None) -> None:
        records = self._read_and_verify() if self.path.exists() else []
        head = records[-1]["record_hash"] if records else None
        if expected_head_hash is not None and head != expected_head_hash:
            raise ANOError("SOURCE_REGISTRY_TRUNCATED", "source registry head does not match its external anchor")
        self._records = records

    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(self._records))

    def head_hash(self) -> str | None:
        return self._records[-1]["record_hash"] if self._records else None

    def checkpoint(
        self, *, registry_id: str, log_id: str, private_key: Ed25519PrivateKey,
        key_id: str, issued_at: str | None = None,
    ) -> dict[str, Any]:
        if not self._records:
            raise ANOError("TRANSPARENCY_LOG_EMPTY", "an empty registry cannot issue a checkpoint")
        return create_source_transparency_checkpoint(
            registry_id=registry_id, log_id=log_id, sequence=len(self._records),
            head_hash=self._records[-1]["record_hash"], private_key=private_key,
            key_id=key_id, issued_at=issued_at,
        )

    def extension_since(self, sequence: int) -> list[dict[str, Any]]:
        if sequence < 0 or sequence > len(self._records):
            raise ANOError("TRANSPARENCY_SEQUENCE_INVALID", "extension sequence is outside the registry")
        return copy.deepcopy(self._records[sequence:])


class TransparencyGossipMonitor:
    """Persist accepted checkpoints and reject rollback, invalid extension, or split views."""

    def __init__(
        self, path: str | Path, catalog: SchemaCatalog,
        checkpoint_verifier: PolicyBoundTransparencyCheckpointVerifier,
        source_verifier: PolicyBoundClusterReportSourceVerifier,
    ) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.checkpoint_verifier = checkpoint_verifier
        self.source_verifier = source_verifier
        self._entries: dict[str, dict[str, Any]] = {}
        self._state_hash: str | None = None
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
            self.catalog.validate("transparency-gossip-state", state)
            material = copy.deepcopy(state)
            material.pop("state_hash")
            if state["state_hash"] != sha256_json(material):
                raise ValueError("state hash mismatch")
            entries: dict[str, dict[str, Any]] = {}
            for item in state["entries"]:
                statement = self.checkpoint_verifier.verify(item["checkpoint_envelope"])
                if statement["registry_id"] != item["registry_id"] or statement["log_id"] != item["log_id"]:
                    raise ValueError("checkpoint state binding mismatch")
                entries[f'{item["log_id"]}|{item["registry_id"]}'] = copy.deepcopy(item)
            self._entries = entries
            self._state_hash = str(state["state_hash"])
        except (OSError, json.JSONDecodeError, ValueError, ANOError) as exc:
            raise ANOError("TRANSPARENCY_GOSSIP_STATE_CORRUPT", "gossip state integrity verification failed") from exc

    def _verify_extension(
        self, records: list[dict[str, Any]], *, start_sequence: int,
        previous_hash: str | None, expected_head: str,
    ) -> None:
        current_hash = previous_hash
        for offset, record in enumerate(records, start=1):
            self.catalog.validate("source-observation-registry-record", record)
            if record["sequence"] != start_sequence + offset or record["previous_hash"] != current_hash:
                raise ANOError("TRANSPARENCY_CONSISTENCY_PROOF_INVALID", "registry extension sequence or link is invalid")
            if record["record_hash"] != SourceObservationRegistry._record_hash(record):
                raise ANOError("TRANSPARENCY_CONSISTENCY_PROOF_INVALID", "registry extension record hash is invalid")
            statement = self.source_verifier.verify(record["report"], record["source_envelope"])
            if (
                record["source_id"] != statement["source_id"]
                or record["source_domain"] != statement["source_domain"]
                or record["run_id"] != record["report"]["run_id"]
                or record["report_hash"] != sha256_json(record["report"])
                or record["source_envelope_hash"] != sha256_json(record["source_envelope"])
            ):
                raise ANOError("TRANSPARENCY_CONSISTENCY_PROOF_INVALID", "registry extension binding is invalid")
            current_hash = record["record_hash"]
        if current_hash != expected_head:
            raise ANOError("TRANSPARENCY_CONSISTENCY_PROOF_INVALID", "registry extension does not reach checkpoint head")

    def accept(
        self, checkpoint_envelope: dict[str, Any], extension_records: list[dict[str, Any]],
    ) -> dict[str, Any]:
        statement = self.checkpoint_verifier.verify(checkpoint_envelope)
        identity = f'{statement["log_id"]}|{statement["registry_id"]}'
        previous = self._entries.get(identity)
        old_sequence = 0 if previous is None else int(previous["sequence"])
        old_head = None if previous is None else str(previous["head_hash"])
        if statement["sequence"] < old_sequence:
            raise ANOError("TRANSPARENCY_ROLLBACK", "checkpoint sequence rolled back")
        if statement["sequence"] == old_sequence:
            if statement["head_hash"] != old_head:
                raise ANOError("TRANSPARENCY_SPLIT_VIEW", "same log sequence has conflicting signed heads")
            return copy.deepcopy(previous)
        if len(extension_records) != statement["sequence"] - old_sequence:
            raise ANOError("TRANSPARENCY_CONSISTENCY_PROOF_INVALID", "registry extension has the wrong length")
        self._verify_extension(
            extension_records, start_sequence=old_sequence, previous_hash=old_head,
            expected_head=statement["head_hash"],
        )
        entry = {
            "registry_id": statement["registry_id"], "log_id": statement["log_id"],
            "sequence": statement["sequence"], "head_hash": statement["head_hash"],
            "accepted_at": utc_now(), "checkpoint_envelope": copy.deepcopy(checkpoint_envelope),
        }
        self._entries[identity] = entry
        material = {
            "monitor_id": "transparency_gossip_monitor", "schema_version": "0.3.0",
            "updated_at": utc_now(), "entries": [self._entries[key] for key in sorted(self._entries)],
        }
        state = {**material, "state_hash": sha256_json(material)}
        self.catalog.validate("transparency-gossip-state", state)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)
        self._state_hash = str(state["state_hash"])
        return copy.deepcopy(entry)

    def entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(self._entries[key]) for key in sorted(self._entries))

    def verify(self, *, expected_state_hash: str | None = None) -> None:
        if self.path.exists():
            self._load()
        if expected_state_hash is not None and self._state_hash != expected_state_hash:
            raise ANOError("TRANSPARENCY_GOSSIP_STATE_ROLLBACK", "gossip state does not match its external anchor")

    def state_hash(self) -> str | None:
        return self._state_hash
