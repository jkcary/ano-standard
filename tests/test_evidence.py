from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ano_runtime import (
    ANOError, IndependentClusterEvidenceVerifier, SchemaCatalog, WitnessedEvidenceLedger,
    create_cluster_evidence_envelope,
)

from tests.support import STANDARD_ROOT, conformance, load_example


class WitnessedEvidenceConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")

    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.verifier = IndependentClusterEvidenceVerifier(
            self.catalog,
            {"witness_ed25519_001": ("independent_evidence_domain", self.private_key.public_key())},
        )

    def envelope(self, report: dict, *, sequence: int = 1, previous_hash: str | None = None, **changes: str) -> dict:
        return create_cluster_evidence_envelope(
            report, self.private_key,
            key_id="witness_ed25519_001",
            runner_domain=changes.get("runner_domain", "cluster_lab_domain"),
            witness_domain=changes.get("witness_domain", "independent_evidence_domain"),
            witness_sequence=sequence,
            previous_envelope_hash=previous_hash,
            witnessed_at=changes.get("witnessed_at"),
        )

    @conformance("S-WIT-001")
    def test_independent_type_bound_witness_rejects_forgery_rebinding_and_self_witness(self) -> None:
        report = load_example("cluster-validation-report")
        envelope = self.envelope(report)
        statement = self.verifier.verify(
            report, envelope, expected_sequence=1, expected_previous_envelope_hash=None,
        )
        self.assertEqual(report["run_id"], statement["subject"]["run_id"])

        rebound = copy.deepcopy(report)
        rebound["scenarios"][0]["evidence"] = "substituted evidence"
        with self.assertRaises(ANOError) as mismatch:
            self.verifier.verify(rebound, envelope, expected_sequence=1, expected_previous_envelope_hash=None)
        self.assertEqual("EVIDENCE_SUBJECT_MISMATCH", mismatch.exception.code)

        forged_key = Ed25519PrivateKey.generate()
        forged = create_cluster_evidence_envelope(
            report, forged_key, key_id="witness_ed25519_001",
            runner_domain="cluster_lab_domain", witness_domain="independent_evidence_domain",
            witness_sequence=1, previous_envelope_hash=None,
        )
        with self.assertRaises(ANOError) as forgery:
            self.verifier.verify(report, forged, expected_sequence=1, expected_previous_envelope_hash=None)
        self.assertEqual("WITNESS_SIGNATURE_INVALID", forgery.exception.code)

        self_witnessed = self.envelope(report, runner_domain="independent_evidence_domain")
        with self.assertRaises(ANOError) as independence:
            self.verifier.verify(report, self_witnessed, expected_sequence=1, expected_previous_envelope_hash=None)
        self.assertEqual("WITNESS_INDEPENDENCE_VIOLATION", independence.exception.code)

        premature = self.envelope(report, witnessed_at="2026-08-27T17:59:00Z")
        with self.assertRaises(ANOError) as invalid_time:
            self.verifier.verify(report, premature, expected_sequence=1, expected_previous_envelope_hash=None)
        self.assertEqual("WITNESS_TIME_INVALID", invalid_time.exception.code)

    @conformance("S-WORM-001")
    def test_ledger_rejects_replay_tamper_and_externally_anchored_truncation(self) -> None:
        first_report = load_example("cluster-validation-report")
        first_envelope = self.envelope(first_report)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "witnessed-evidence.jsonl"
            ledger = WitnessedEvidenceLedger(path, self.catalog, self.verifier)
            first_record = ledger.append(first_report, first_envelope)

            with self.assertRaises(ANOError) as replay:
                ledger.append(first_report, first_envelope)
            self.assertEqual("EVIDENCE_REPLAY", replay.exception.code)

            second_report = copy.deepcopy(first_report)
            second_report["run_id"] = "lab_demo_002"
            second_report["namespace"] = "ano-alpha8-b2c3d4e5"
            second_envelope = self.envelope(
                second_report, sequence=2,
                previous_hash=WitnessedEvidenceLedger.envelope_hash(first_envelope),
            )
            lock_path = path.with_suffix(path.suffix + ".lock")
            lock_path.write_text("other-writer", encoding="utf-8")
            with self.assertRaises(ANOError) as concurrent:
                ledger.append(second_report, second_envelope)
            self.assertEqual("EVIDENCE_LEDGER_CONCURRENT_WRITE", concurrent.exception.code)
            lock_path.unlink()
            ledger.append(second_report, second_envelope)
            anchored_head = ledger.head_hash()
            ledger.verify(expected_head_hash=anchored_head)

            original_lines = path.read_text(encoding="utf-8").splitlines()
            tampered = original_lines[0].replace("service account token absent", "substituted token evidence")
            self.assertNotEqual(original_lines[0], tampered)
            path.write_text(tampered + "\n" + original_lines[1] + "\n", encoding="utf-8")
            with self.assertRaises(ANOError) as corrupt:
                WitnessedEvidenceLedger(path, self.catalog, self.verifier)
            self.assertEqual("EVIDENCE_LEDGER_CORRUPT", corrupt.exception.code)

            path.write_text(original_lines[0] + "\n", encoding="utf-8")
            truncated = WitnessedEvidenceLedger(path, self.catalog, self.verifier)
            self.assertEqual(first_record["record_hash"], truncated.head_hash())
            with self.assertRaises(ANOError) as rollback:
                truncated.verify(expected_head_hash=anchored_head)
            self.assertEqual("EVIDENCE_LEDGER_TRUNCATED", rollback.exception.code)


if __name__ == "__main__":
    unittest.main()
