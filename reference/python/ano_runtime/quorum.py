from __future__ import annotations

import copy
import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import ANOError
from .evidence import WitnessedEvidenceLedger
from .schema import SchemaCatalog
from .util import new_id, parse_timestamp, sha256_json, utc_now
from .witness_policy import PolicyBoundClusterEvidenceVerifier


def create_cluster_evidence_quorum_bundle(
    report: dict[str, Any], envelopes: list[dict[str, Any]], quorum_policy: dict[str, Any],
    *, created_at: str | None = None,
    source_attestations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    bundle = {
        "bundle_id": new_id("qeb"), "schema_version": "0.3.0",
        "report_run_id": report["run_id"], "report_hash": sha256_json(report),
        "quorum_policy_id": quorum_policy["policy_id"],
        "quorum_policy_version": quorum_policy["policy_version"],
        "created_at": created_at or utc_now(), "envelopes": copy.deepcopy(envelopes),
    }
    if source_attestations is not None:
        bundle["source_attestations"] = copy.deepcopy(source_attestations)
    return bundle


class IndependentWitnessQuorumVerifier:
    """Require a threshold of cryptographically valid witnesses from distinct trust domains."""

    def __init__(
        self,
        catalog: SchemaCatalog,
        trust_policy: dict[str, Any],
        quorum_policy: dict[str, Any],
        trusted_public_keys: dict[str, Ed25519PublicKey],
        *,
        expected_trust_policy_id: str,
        minimum_trust_policy_version: int,
        expected_trust_policy_hash: str,
        expected_quorum_policy_id: str,
        minimum_quorum_policy_version: int,
        expected_quorum_policy_hash: str,
        maximum_future_skew_seconds: int = 60,
    ) -> None:
        trusted_quorum_policy = copy.deepcopy(quorum_policy)
        catalog.validate("witness-quorum-policy", trusted_quorum_policy)
        if trusted_quorum_policy["policy_id"] != expected_quorum_policy_id:
            raise ANOError("WITNESS_QUORUM_POLICY_IDENTITY", "quorum policy identity does not match its trust root")
        if trusted_quorum_policy["policy_version"] < minimum_quorum_policy_version:
            raise ANOError("WITNESS_QUORUM_POLICY_ROLLBACK", "quorum policy version is older than its configured floor")
        if sha256_json(trusted_quorum_policy) != expected_quorum_policy_hash:
            raise ANOError("WITNESS_QUORUM_POLICY_INTEGRITY", "quorum policy does not match its integrity anchor")
        if trusted_quorum_policy["threshold"] > len(trusted_quorum_policy["members"]):
            raise ANOError("WITNESS_QUORUM_POLICY_INVALID", "quorum threshold exceeds the member count")

        catalog.validate("witness-trust-policy", trust_policy)
        trust_entries = {str(item["key_id"]): item for item in trust_policy["keys"]}
        members: dict[str, dict[str, Any]] = {}
        domains: set[str] = set()
        key_owners: dict[str, str] = {}
        for member in trusted_quorum_policy["members"]:
            member_id, domain = str(member["member_id"]), str(member["witness_domain"])
            if member_id in members or domain in domains:
                raise ANOError("WITNESS_QUORUM_POLICY_INVALID", "quorum members must have unique identities and trust domains")
            for key_id in member["key_ids"]:
                if key_id in key_owners:
                    raise ANOError("WITNESS_QUORUM_POLICY_INVALID", "a witness key cannot belong to multiple quorum members")
                trust_entry = trust_entries.get(str(key_id))
                if trust_entry is None or trust_entry["witness_domain"] != domain:
                    raise ANOError("WITNESS_QUORUM_POLICY_INVALID", "quorum key does not match its lifecycle trust domain")
                key_owners[str(key_id)] = member_id
            members[member_id] = member
            domains.add(domain)
        required = set(trusted_quorum_policy["required_member_ids"])
        if not required <= set(members):
            raise ANOError("WITNESS_QUORUM_POLICY_INVALID", "required quorum member is not declared")
        self._catalog = catalog
        self._trust_verifier = PolicyBoundClusterEvidenceVerifier(
            catalog, trust_policy, trusted_public_keys,
            expected_policy_id=expected_trust_policy_id,
            minimum_policy_version=minimum_trust_policy_version,
            expected_policy_hash=expected_trust_policy_hash,
            maximum_future_skew_seconds=maximum_future_skew_seconds,
        )
        self._quorum_policy = trusted_quorum_policy
        self._members = members
        self._key_owners = key_owners
        self._required = required
        self._future_skew = timedelta(seconds=maximum_future_skew_seconds)

    def verify(
        self,
        report: dict[str, Any],
        bundle: dict[str, Any],
        *,
        chain_heads: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self._catalog.validate("cluster-evidence-quorum-bundle", bundle)
        if bundle["report_run_id"] != report["run_id"] or bundle["report_hash"] != sha256_json(report):
            raise ANOError("WITNESS_QUORUM_SUBJECT_MISMATCH", "quorum bundle does not bind this cluster report")
        if (
            bundle["quorum_policy_id"] != self._quorum_policy["policy_id"]
            or bundle["quorum_policy_version"] != self._quorum_policy["policy_version"]
        ):
            raise ANOError("WITNESS_QUORUM_POLICY_MISMATCH", "quorum bundle names a different policy revision")
        heads = copy.deepcopy(chain_heads or {})
        unknown_heads = set(heads) - set(self._members)
        if unknown_heads:
            raise ANOError("WITNESS_QUORUM_CHAIN_INVALID", "chain state contains an unknown quorum member")
        for member_id, head in heads.items():
            if set(head) != {"sequence", "envelope_hash"} or not isinstance(head["sequence"], int) or head["sequence"] < 1:
                raise ANOError("WITNESS_QUORUM_CHAIN_INVALID", f"chain head for {member_id} is malformed")
            envelope_hash = head["envelope_hash"]
            if not isinstance(envelope_hash, str) or len(envelope_hash) != 71 or not envelope_hash.startswith("sha256:"):
                raise ANOError("WITNESS_QUORUM_CHAIN_INVALID", f"chain hash for {member_id} is malformed")

        statements: dict[str, dict[str, Any]] = {}
        for envelope in bundle["envelopes"]:
            key_id = str(envelope["signatures"][0]["keyid"])
            member_id = self._key_owners.get(key_id)
            if member_id is None:
                raise ANOError("WITNESS_QUORUM_UNTRUSTED_MEMBER", "bundle contains a key outside the quorum policy")
            if member_id in statements:
                raise ANOError("WITNESS_QUORUM_DUPLICATE_MEMBER", "one quorum member cannot be counted more than once")
            previous = heads.get(member_id)
            statement = self._trust_verifier.verify(
                report, envelope,
                expected_sequence=1 if previous is None else int(previous["sequence"]) + 1,
                expected_previous_envelope_hash=None if previous is None else str(previous["envelope_hash"]),
            )
            statements[member_id] = statement
            heads[member_id] = {
                "sequence": statement["witness_sequence"],
                "envelope_hash": WitnessedEvidenceLedger.envelope_hash(envelope),
            }
        accepted = set(statements)
        if len(accepted) < self._quorum_policy["threshold"]:
            raise ANOError("WITNESS_QUORUM_NOT_MET", "valid independent witness count is below the required threshold")
        if not self._required <= accepted:
            raise ANOError("WITNESS_QUORUM_REQUIRED_MEMBER_MISSING", "a mandatory quorum member is absent")
        created_at = parse_timestamp(bundle["created_at"])
        witness_times = [parse_timestamp(item["witnessed_at"]) for item in statements.values()]
        if any(created_at < witnessed_at for witnessed_at in witness_times):
            raise ANOError("WITNESS_QUORUM_TIME_INVALID", "quorum bundle predates one of its witness statements")
        spread = max(witness_times) - min(witness_times)
        if spread > timedelta(seconds=self._quorum_policy["maximum_witness_spread_seconds"]):
            raise ANOError("WITNESS_QUORUM_TIME_INVALID", "witness statements exceed the allowed collection window")
        if any(
            created_at - witnessed_at > timedelta(seconds=self._quorum_policy["maximum_bundle_delay_seconds"])
            for witnessed_at in witness_times
        ):
            raise ANOError("WITNESS_QUORUM_TIME_INVALID", "quorum bundle was assembled too long after witnessing")
        if created_at > parse_timestamp(utc_now()) + self._future_skew:
            raise ANOError("WITNESS_QUORUM_TIME_INVALID", "quorum bundle timestamp is too far in the future")
        member_key_ids = {
            self._key_owners[str(envelope["signatures"][0]["keyid"])]: str(envelope["signatures"][0]["keyid"])
            for envelope in bundle["envelopes"]
        }
        return {
            "member_ids": sorted(accepted), "member_key_ids": member_key_ids,
            "statements": copy.deepcopy(statements), "chain_heads": heads,
        }


class QuorumEvidenceLedger:
    """Append-only quorum archive with independent per-member witness-chain heads."""

    def __init__(
        self, path: str | Path, catalog: SchemaCatalog, verifier: IndependentWitnessQuorumVerifier,
        *, initial_chain_heads: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.verifier = verifier
        self._initial_heads = copy.deepcopy(initial_chain_heads or {})
        self._records, self._chain_heads = self._read_and_verify() if self.path.exists() else ([], copy.deepcopy(self._initial_heads))

    @staticmethod
    def _record_hash(record: dict[str, Any]) -> str:
        material = copy.deepcopy(record)
        material.pop("record_hash", None)
        return sha256_json(material)

    def _read_and_verify(self) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
        records: list[dict[str, Any]] = []
        heads = copy.deepcopy(self._initial_heads)
        previous_hash: str | None = None
        seen_runs: set[str] = set()
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    self.catalog.validate("quorum-evidence-ledger-record", record)
                    if record["sequence"] != len(records) + 1 or record["previous_hash"] != previous_hash:
                        raise ValueError(f"record sequence or predecessor mismatch at line {line_number}")
                    if record["record_hash"] != self._record_hash(record):
                        raise ValueError(f"record hash mismatch at line {line_number}")
                    if record["bundle_hash"] != sha256_json(record["bundle"]):
                        raise ValueError(f"bundle hash mismatch at line {line_number}")
                    run_id = str(record["report"]["run_id"])
                    if run_id in seen_runs:
                        raise ValueError(f"duplicate run id at line {line_number}")
                    verified = self.verifier.verify(record["report"], record["bundle"], chain_heads=heads)
                    heads = verified["chain_heads"]
                    records.append(record)
                    seen_runs.add(run_id)
                    previous_hash = record["record_hash"]
        except (OSError, json.JSONDecodeError, ValueError, ANOError) as exc:
            raise ANOError("QUORUM_LEDGER_CORRUPT", "quorum evidence ledger integrity verification failed") from exc
        return records, heads

    def append(self, report: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ANOError("QUORUM_LEDGER_CONCURRENT_WRITE", "quorum ledger writer lock is already held") from exc
        try:
            os.write(lock_fd, str(os.getpid()).encode("ascii"))
            os.fsync(lock_fd)
            disk_records, disk_heads = self._read_and_verify() if self.path.exists() else ([], copy.deepcopy(self._initial_heads))
            if [item["record_hash"] for item in disk_records] != [item["record_hash"] for item in self._records]:
                raise ANOError("QUORUM_LEDGER_CONCURRENT_WRITE", "quorum ledger changed since it was opened")
            if disk_heads != self._chain_heads:
                raise ANOError("QUORUM_LEDGER_CONCURRENT_WRITE", "quorum witness chain state changed since it was opened")
            if any(item["report"]["run_id"] == report["run_id"] for item in self._records):
                raise ANOError("EVIDENCE_REPLAY", "cluster run is already present in the quorum ledger")
            verified = self.verifier.verify(report, bundle, chain_heads=self._chain_heads)
            material = {
                "record_id": new_id("qld"), "schema_version": "0.3.0",
                "sequence": len(self._records) + 1,
                "previous_hash": self._records[-1]["record_hash"] if self._records else None,
                "bundle_hash": sha256_json(bundle), "appended_at": utc_now(),
                "report": copy.deepcopy(report), "bundle": copy.deepcopy(bundle),
            }
            record = {**material, "record_hash": self._record_hash(material)}
            self.catalog.validate("quorum-evidence-ledger-record", record)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._records.append(copy.deepcopy(record))
            self._chain_heads = verified["chain_heads"]
            return copy.deepcopy(record)
        finally:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)

    def verify(self, *, expected_head_hash: str | None = None) -> None:
        records, heads = self._read_and_verify() if self.path.exists() else ([], copy.deepcopy(self._initial_heads))
        head = records[-1]["record_hash"] if records else None
        if expected_head_hash is not None and head != expected_head_hash:
            raise ANOError("QUORUM_LEDGER_TRUNCATED", "quorum ledger head does not match the external anchor")
        self._records, self._chain_heads = records, heads

    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(self._records))

    def head_hash(self) -> str | None:
        return self._records[-1]["record_hash"] if self._records else None

    def chain_heads(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._chain_heads)
