from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ano_runtime import (
    ANOError, PolicyBoundClusterEvidenceVerifier, SchemaCatalog,
    WitnessedEvidenceLedger, create_cluster_evidence_envelope,
    sha256_json, witness_public_key_fingerprint,
)

from tests.support import STANDARD_ROOT, conformance, load_example


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class WitnessKeyLifecycleConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")

    @staticmethod
    def key_entry(
        key_id: str, private_key: Ed25519PrivateKey, *, status: str,
        valid_from: datetime, valid_until: datetime,
        revoked_at: datetime | None = None, revocation_mode: str = "none",
    ) -> dict:
        return {
            "key_id": key_id, "algorithm": "Ed25519", "witness_domain": "independent_evidence_domain",
            "public_key_sha256": witness_public_key_fingerprint(private_key.public_key()),
            "status": status, "valid_from": timestamp(valid_from), "valid_until": timestamp(valid_until),
            "revoked_at": None if revoked_at is None else timestamp(revoked_at),
            "revocation_mode": revocation_mode,
        }

    @staticmethod
    def policy(entries: list[dict], issued_at: datetime) -> dict:
        return {
            "policy_id": "wtp_test_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(issued_at), "keys": entries,
        }

    @staticmethod
    def envelope(
        report: dict, key: Ed25519PrivateKey, key_id: str, witnessed_at: datetime,
        *, sequence: int = 1, previous: str | None = None,
    ) -> dict:
        return create_cluster_evidence_envelope(
            report, key, key_id=key_id, runner_domain="cluster_lab_domain",
            witness_domain="independent_evidence_domain", witness_sequence=sequence,
            previous_envelope_hash=previous, witnessed_at=timestamp(witnessed_at),
        )

    @conformance("S-KROT-001")
    def test_rotation_validity_fingerprint_and_revocation_are_fail_closed(self) -> None:
        report = load_example("cluster-validation-report")
        now = datetime.now(timezone.utc)
        old_time, rotation_time, new_time = now - timedelta(minutes=20), now - timedelta(minutes=10), now - timedelta(minutes=5)
        old_key, new_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        old_envelope = self.envelope(report, old_key, "witness_old_001", old_time)
        next_report = copy.deepcopy(report)
        next_report["run_id"] = "lab_demo_002"
        next_report["namespace"] = "ano-alpha8-b2c3d4e5"
        new_envelope = self.envelope(
            next_report, new_key, "witness_new_001", new_time, sequence=2,
            previous=WitnessedEvidenceLedger.envelope_hash(old_envelope),
        )
        rotation_policy = self.policy([
            self.key_entry(
                "witness_old_001", old_key, status="retired",
                valid_from=now - timedelta(days=1), valid_until=rotation_time,
            ),
            self.key_entry(
                "witness_new_001", new_key, status="active",
                valid_from=rotation_time, valid_until=now + timedelta(days=1),
            ),
        ], now)
        policy_arguments = {
            "expected_policy_id": "wtp_test_001", "minimum_policy_version": 1,
            "expected_policy_hash": sha256_json(rotation_policy),
        }
        verifier = PolicyBoundClusterEvidenceVerifier(
            self.catalog, rotation_policy,
            {"witness_old_001": old_key.public_key(), "witness_new_001": new_key.public_key()},
            **policy_arguments,
        )
        verifier.verify(report, old_envelope, expected_sequence=1, expected_previous_envelope_hash=None)
        verifier.verify(
            next_report, new_envelope, expected_sequence=2,
            expected_previous_envelope_hash=WitnessedEvidenceLedger.envelope_hash(old_envelope),
        )

        expired_old = self.envelope(report, old_key, "witness_old_001", new_time)
        with self.assertRaises(ANOError) as expired:
            verifier.verify(report, expired_old, expected_sequence=1, expected_previous_envelope_hash=None)
        self.assertEqual("WITNESS_KEY_OUTSIDE_VALIDITY", expired.exception.code)

        with self.assertRaises(ANOError) as substituted:
            PolicyBoundClusterEvidenceVerifier(
                self.catalog, rotation_policy,
                {"witness_old_001": Ed25519PrivateKey.generate().public_key(), "witness_new_001": new_key.public_key()},
                **policy_arguments,
            )
        self.assertEqual("WITNESS_KEY_FINGERPRINT_MISMATCH", substituted.exception.code)

        revoked_entry = self.key_entry(
            "witness_old_001", old_key, status="revoked",
            valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=1),
            revoked_at=rotation_time, revocation_mode="prospective",
        )
        prospective_policy = self.policy([revoked_entry], now)
        prospective = PolicyBoundClusterEvidenceVerifier(
            self.catalog, prospective_policy, {"witness_old_001": old_key.public_key()},
            expected_policy_id="wtp_test_001", minimum_policy_version=1,
            expected_policy_hash=sha256_json(prospective_policy),
        )
        prospective.verify(report, old_envelope, expected_sequence=1, expected_previous_envelope_hash=None)
        with self.assertRaises(ANOError) as revoked:
            prospective.verify(report, expired_old, expected_sequence=1, expected_previous_envelope_hash=None)
        self.assertEqual("WITNESS_KEY_REVOKED", revoked.exception.code)

        retroactive_entry = copy.deepcopy(revoked_entry)
        retroactive_entry["revocation_mode"] = "retroactive"
        retroactive_policy = self.policy([retroactive_entry], now)
        retroactive = PolicyBoundClusterEvidenceVerifier(
            self.catalog, retroactive_policy, {"witness_old_001": old_key.public_key()},
            expected_policy_id="wtp_test_001", minimum_policy_version=1,
            expected_policy_hash=sha256_json(retroactive_policy),
        )
        with self.assertRaises(ANOError) as retroactively_revoked:
            retroactive.verify(report, old_envelope, expected_sequence=1, expected_previous_envelope_hash=None)
        self.assertEqual("WITNESS_KEY_REVOKED", retroactively_revoked.exception.code)

        tampered_policy = copy.deepcopy(rotation_policy)
        tampered_policy["keys"][0]["status"] = "active"
        with self.assertRaises(ANOError) as tampered:
            PolicyBoundClusterEvidenceVerifier(
                self.catalog, tampered_policy,
                {"witness_old_001": old_key.public_key(), "witness_new_001": new_key.public_key()},
                **policy_arguments,
            )
        self.assertEqual("WITNESS_KEY_POLICY_INTEGRITY", tampered.exception.code)

        with self.assertRaises(ANOError) as rollback:
            PolicyBoundClusterEvidenceVerifier(
                self.catalog, rotation_policy,
                {"witness_old_001": old_key.public_key(), "witness_new_001": new_key.public_key()},
                expected_policy_id="wtp_test_001", minimum_policy_version=2,
                expected_policy_hash=sha256_json(rotation_policy),
            )
        self.assertEqual("WITNESS_KEY_POLICY_ROLLBACK", rollback.exception.code)

        mutable_policy = copy.deepcopy(rotation_policy)
        snapshot_verifier = PolicyBoundClusterEvidenceVerifier(
            self.catalog, mutable_policy,
            {"witness_old_001": old_key.public_key(), "witness_new_001": new_key.public_key()},
            expected_policy_id="wtp_test_001", minimum_policy_version=1,
            expected_policy_hash=sha256_json(mutable_policy),
        )
        mutable_policy["keys"][0]["status"] = "active"
        mutable_policy["keys"][0]["valid_until"] = timestamp(now + timedelta(days=1))
        with self.assertRaises(ANOError) as post_init_mutation:
            snapshot_verifier.verify(report, expired_old, expected_sequence=1, expected_previous_envelope_hash=None)
        self.assertEqual("WITNESS_KEY_OUTSIDE_VALIDITY", post_init_mutation.exception.code)


if __name__ == "__main__":
    unittest.main()
