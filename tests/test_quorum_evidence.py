from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ano_runtime import (
    ANOError, IndependentWitnessQuorumVerifier, QuorumEvidenceLedger, SchemaCatalog,
    WitnessedEvidenceLedger, create_cluster_evidence_envelope,
    create_cluster_evidence_quorum_bundle, sha256_json, witness_public_key_fingerprint,
)

from tests.support import STANDARD_ROOT, conformance, load_example


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def trust_entry(
    key_id: str, key: Ed25519PrivateKey, domain: str, *, now: datetime,
    status: str = "active", valid_from: datetime | None = None,
    valid_until: datetime | None = None,
) -> dict:
    return {
        "key_id": key_id, "algorithm": "Ed25519", "witness_domain": domain,
        "public_key_sha256": witness_public_key_fingerprint(key.public_key()),
        "status": status, "valid_from": timestamp(valid_from or now - timedelta(days=1)),
        "valid_until": timestamp(valid_until or now + timedelta(days=1)),
        "revoked_at": None, "revocation_mode": "none",
    }


def envelope(
    report: dict, key: Ed25519PrivateKey, key_id: str, domain: str, witnessed_at: datetime,
    *, sequence: int = 1, previous: str | None = None,
) -> dict:
    return create_cluster_evidence_envelope(
        report, key, key_id=key_id, runner_domain="cluster_lab_domain", witness_domain=domain,
        witness_sequence=sequence, previous_envelope_hash=previous, witnessed_at=timestamp(witnessed_at),
    )


class WitnessQuorumConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")

    def verifier(
        self, trust_policy: dict, quorum_policy: dict,
        keys: dict[str, Ed25519PrivateKey], *, quorum_floor: int = 1,
        quorum_hash: str | None = None,
    ) -> IndependentWitnessQuorumVerifier:
        return IndependentWitnessQuorumVerifier(
            self.catalog, trust_policy, quorum_policy,
            {key_id: key.public_key() for key_id, key in keys.items()},
            expected_trust_policy_id=trust_policy["policy_id"], minimum_trust_policy_version=1,
            expected_trust_policy_hash=sha256_json(trust_policy),
            expected_quorum_policy_id=quorum_policy["policy_id"], minimum_quorum_policy_version=quorum_floor,
            expected_quorum_policy_hash=quorum_hash or sha256_json(quorum_policy),
        )

    @conformance("S-QUORUM-001")
    def test_threshold_counts_independent_members_not_keys_and_rejects_policy_attacks(self) -> None:
        now = datetime.now(timezone.utc)
        report = load_example("cluster-validation-report")
        keys = {name: Ed25519PrivateKey.generate() for name in ("key_a", "key_a_next", "key_b", "key_c")}
        domains = {"key_a": "evidence_domain_a", "key_a_next": "evidence_domain_a", "key_b": "evidence_domain_b", "key_c": "evidence_domain_c"}
        trust_policy = {
            "policy_id": "wtp_quorum_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now),
            "keys": [trust_entry(key_id, key, domains[key_id], now=now) for key_id, key in keys.items()],
        }
        quorum_policy = {
            "policy_id": "wqp_quorum_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "threshold": 2, "required_member_ids": [],
            "maximum_witness_spread_seconds": 300, "maximum_bundle_delay_seconds": 600,
            "members": [
                {"member_id": "member_a", "witness_domain": "evidence_domain_a", "key_ids": ["key_a", "key_a_next"]},
                {"member_id": "member_b", "witness_domain": "evidence_domain_b", "key_ids": ["key_b"]},
                {"member_id": "member_c", "witness_domain": "evidence_domain_c", "key_ids": ["key_c"]},
            ],
        }
        verifier = self.verifier(trust_policy, quorum_policy, keys)
        witnessed = now - timedelta(minutes=1)
        env_a = envelope(report, keys["key_a"], "key_a", domains["key_a"], witnessed)
        env_b = envelope(report, keys["key_b"], "key_b", domains["key_b"], witnessed)
        valid_bundle = create_cluster_evidence_quorum_bundle(
            report, [env_a, env_b], quorum_policy, created_at=timestamp(now),
        )
        result = verifier.verify(report, valid_bundle)
        self.assertEqual(["member_a", "member_b"], result["member_ids"])

        insufficient = create_cluster_evidence_quorum_bundle(report, [env_a], quorum_policy, created_at=timestamp(now))
        with self.assertRaises(ANOError) as below_threshold:
            verifier.verify(report, insufficient)
        self.assertEqual("WITNESS_QUORUM_NOT_MET", below_threshold.exception.code)

        env_a_next = envelope(report, keys["key_a_next"], "key_a_next", domains["key_a_next"], witnessed)
        duplicate_member = create_cluster_evidence_quorum_bundle(
            report, [env_a, env_a_next], quorum_policy, created_at=timestamp(now),
        )
        with self.assertRaises(ANOError) as duplicate:
            verifier.verify(report, duplicate_member)
        self.assertEqual("WITNESS_QUORUM_DUPLICATE_MEMBER", duplicate.exception.code)

        forged_b = envelope(report, Ed25519PrivateKey.generate(), "key_b", domains["key_b"], witnessed)
        forged_bundle = create_cluster_evidence_quorum_bundle(
            report, [env_a, forged_b], quorum_policy, created_at=timestamp(now),
        )
        with self.assertRaises(ANOError) as forged:
            verifier.verify(report, forged_bundle)
        self.assertEqual("WITNESS_SIGNATURE_INVALID", forged.exception.code)

        stale_a = envelope(
            report, keys["key_a"], "key_a", domains["key_a"], now - timedelta(minutes=20),
        )
        stale_mix = create_cluster_evidence_quorum_bundle(
            report, [stale_a, env_b], quorum_policy, created_at=timestamp(now),
        )
        with self.assertRaises(ANOError) as stale:
            verifier.verify(report, stale_mix)
        self.assertEqual("WITNESS_QUORUM_TIME_INVALID", stale.exception.code)

        required_policy = copy.deepcopy(quorum_policy)
        required_policy["required_member_ids"] = ["member_c"]
        required_verifier = self.verifier(trust_policy, required_policy, keys)
        required_bundle = create_cluster_evidence_quorum_bundle(
            report, [env_a, env_b], required_policy, created_at=timestamp(now),
        )
        with self.assertRaises(ANOError) as mandatory_missing:
            required_verifier.verify(report, required_bundle)
        self.assertEqual("WITNESS_QUORUM_REQUIRED_MEMBER_MISSING", mandatory_missing.exception.code)

        duplicate_domain_policy = copy.deepcopy(quorum_policy)
        duplicate_domain_policy["members"][2]["witness_domain"] = "evidence_domain_b"
        duplicate_domain_policy["members"][2]["key_ids"] = ["key_b"]
        with self.assertRaises(ANOError) as duplicate_domain:
            self.verifier(trust_policy, duplicate_domain_policy, keys)
        self.assertEqual("WITNESS_QUORUM_POLICY_INVALID", duplicate_domain.exception.code)

        tampered_policy = copy.deepcopy(quorum_policy)
        tampered_policy["threshold"] = 1
        with self.assertRaises(ANOError) as tampered:
            self.verifier(trust_policy, tampered_policy, keys, quorum_hash=sha256_json(quorum_policy))
        self.assertEqual("WITNESS_QUORUM_POLICY_INTEGRITY", tampered.exception.code)
        with self.assertRaises(ANOError) as rollback:
            self.verifier(trust_policy, quorum_policy, keys, quorum_floor=2)
        self.assertEqual("WITNESS_QUORUM_POLICY_ROLLBACK", rollback.exception.code)

    @conformance("S-QARC-001")
    def test_quorum_ledger_preserves_rotated_member_chains_and_detects_tamper_or_truncation(self) -> None:
        now = datetime.now(timezone.utc)
        old_time, rotation_time, new_time = now - timedelta(minutes=20), now - timedelta(minutes=10), now - timedelta(minutes=5)
        old_a, new_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        keys = {"key_a_old": old_a, "key_a_new": new_a, "key_b": key_b}
        trust_policy = {
            "policy_id": "wtp_archive_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "keys": [
                trust_entry("key_a_old", old_a, "evidence_domain_a", now=now, status="retired", valid_until=rotation_time),
                trust_entry("key_a_new", new_a, "evidence_domain_a", now=now, valid_from=rotation_time),
                trust_entry("key_b", key_b, "evidence_domain_b", now=now),
            ],
        }
        quorum_policy = {
            "policy_id": "wqp_archive_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "threshold": 2, "required_member_ids": [],
            "maximum_witness_spread_seconds": 300, "maximum_bundle_delay_seconds": 600,
            "members": [
                {"member_id": "member_a", "witness_domain": "evidence_domain_a", "key_ids": ["key_a_old", "key_a_new"]},
                {"member_id": "member_b", "witness_domain": "evidence_domain_b", "key_ids": ["key_b"]},
            ],
        }
        verifier = self.verifier(trust_policy, quorum_policy, keys)
        first_report = load_example("cluster-validation-report")
        old_a_envelope = envelope(first_report, old_a, "key_a_old", "evidence_domain_a", old_time)
        first_b_envelope = envelope(first_report, key_b, "key_b", "evidence_domain_b", old_time)
        first_bundle = create_cluster_evidence_quorum_bundle(
            first_report, [old_a_envelope, first_b_envelope], quorum_policy,
            created_at=timestamp(now - timedelta(minutes=15)),
        )

        second_report = copy.deepcopy(first_report)
        second_report["run_id"] = "lab_demo_002"
        second_report["namespace"] = "ano-alpha8-b2c3d4e5"
        new_a_envelope = envelope(
            second_report, new_a, "key_a_new", "evidence_domain_a", new_time, sequence=2,
            previous=WitnessedEvidenceLedger.envelope_hash(old_a_envelope),
        )
        second_b_envelope = envelope(
            second_report, key_b, "key_b", "evidence_domain_b", new_time, sequence=2,
            previous=WitnessedEvidenceLedger.envelope_hash(first_b_envelope),
        )
        second_bundle = create_cluster_evidence_quorum_bundle(
            second_report, [new_a_envelope, second_b_envelope], quorum_policy, created_at=timestamp(now),
        )

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = directory / "quorum-evidence.jsonl"
            trust_path, quorum_path = directory / "trust.json", directory / "quorum.json"
            report_path, bundle_path = directory / "report.json", directory / "bundle.json"
            trust_path.write_text(json.dumps(trust_policy), encoding="utf-8")
            quorum_path.write_text(json.dumps(quorum_policy), encoding="utf-8")
            report_path.write_text(json.dumps(first_report), encoding="utf-8")
            bundle_path.write_text(json.dumps(first_bundle), encoding="utf-8")
            trusted_key_arguments: list[str] = []
            for key_id, key in keys.items():
                public_path = directory / f"{key_id}.pub.pem"
                public_path.write_bytes(key.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
                ))
                trusted_key_arguments.extend(["--trusted-key", f"{key_id}={public_path}"])
            cli_ledger = directory / "cli-quorum-evidence.jsonl"
            cli_command = [
                sys.executable, str(STANDARD_ROOT / "tools" / "archive_quorum_evidence.py"),
                "--report", str(report_path), "--bundle", str(bundle_path),
                "--trust-policy", str(trust_path), "--expected-trust-policy-id", "wtp_archive_001",
                "--minimum-trust-policy-version", "1", "--expected-trust-policy-hash", sha256_json(trust_policy),
                "--quorum-policy", str(quorum_path), "--expected-quorum-policy-id", "wqp_archive_001",
                "--minimum-quorum-policy-version", "1", "--expected-quorum-policy-hash", sha256_json(quorum_policy),
                "--ledger", str(cli_ledger), *trusted_key_arguments,
            ]
            cli = subprocess.run(
                cli_command, cwd=STANDARD_ROOT, text=True, capture_output=True, timeout=20, check=False,
            )
            self.assertEqual(0, cli.returncode, cli.stderr)
            self.assertEqual(1, json.loads(cli.stdout)["sequence"])
            imported_heads = directory / "initial-heads.json"
            imported_heads.write_text("{}\n", encoding="utf-8")
            unanchored_import = subprocess.run(
                [*cli_command, "--initial-chain-heads", str(imported_heads)],
                cwd=STANDARD_ROOT, text=True, capture_output=True, timeout=20, check=False,
            )
            self.assertNotEqual(0, unanchored_import.returncode)
            self.assertIn("must be supplied together", unanchored_import.stderr)

            ledger = QuorumEvidenceLedger(path, self.catalog, verifier)
            first_record = ledger.append(first_report, first_bundle)
            lock_path = path.with_suffix(path.suffix + ".lock")
            lock_path.write_text("other-writer", encoding="utf-8")
            with self.assertRaises(ANOError) as concurrent:
                ledger.append(second_report, second_bundle)
            self.assertEqual("QUORUM_LEDGER_CONCURRENT_WRITE", concurrent.exception.code)
            lock_path.unlink()
            ledger.append(second_report, second_bundle)
            anchored_head = ledger.head_hash()
            self.assertEqual(2, ledger.chain_heads()["member_a"]["sequence"])
            reopened = QuorumEvidenceLedger(path, self.catalog, verifier)
            self.assertEqual(2, len(reopened.records()))
            reopened.verify(expected_head_hash=anchored_head)

            original_lines = path.read_text(encoding="utf-8").splitlines()
            tampered = original_lines[0].replace("service account token absent", "substituted quorum evidence")
            self.assertNotEqual(original_lines[0], tampered)
            path.write_text(tampered + "\n" + original_lines[1] + "\n", encoding="utf-8")
            with self.assertRaises(ANOError) as corrupt:
                QuorumEvidenceLedger(path, self.catalog, verifier)
            self.assertEqual("QUORUM_LEDGER_CORRUPT", corrupt.exception.code)

            path.write_text(original_lines[0] + "\n", encoding="utf-8")
            truncated = QuorumEvidenceLedger(path, self.catalog, verifier)
            self.assertEqual(first_record["record_hash"], truncated.head_hash())
            with self.assertRaises(ANOError) as rollback:
                truncated.verify(expected_head_hash=anchored_head)
            self.assertEqual("QUORUM_LEDGER_TRUNCATED", rollback.exception.code)


if __name__ == "__main__":
    unittest.main()
