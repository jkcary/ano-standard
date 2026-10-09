from __future__ import annotations

import copy
import unittest

from ano_runtime import ANOError, ClusterValidationEvidenceVerifier, SchemaCatalog

from tests.support import STANDARD_ROOT, conformance, load_example


class ClusterLabConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")
        cls.verifier = ClusterValidationEvidenceVerifier(cls.catalog)

    @conformance("S-LAB-001")
    def test_cluster_evidence_requires_all_scenarios_and_verified_cleanup(self) -> None:
        report = load_example("cluster-validation-report")
        self.verifier.verify(report)

        failed = copy.deepcopy(report)
        failed["scenarios"][4]["status"] = "failed"
        failed["status"] = "failed"
        with self.assertRaises(ANOError) as scenario_error:
            self.verifier.verify(failed)
        self.assertEqual("CLUSTER_VALIDATION_FAILED", scenario_error.exception.code)

        unclean = copy.deepcopy(report)
        unclean["cleanup"]["verified"] = False
        with self.assertRaises(ANOError) as cleanup_error:
            self.verifier.verify(unclean)
        self.assertEqual("CLUSTER_CLEANUP_UNVERIFIED", cleanup_error.exception.code)


if __name__ == "__main__":
    unittest.main()
