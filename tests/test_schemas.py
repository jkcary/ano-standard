from __future__ import annotations

import copy
import json
import unittest

from ano_runtime import ANOError, SchemaCatalog

from tests.support import EXAMPLES, STANDARD_ROOT, conformance, load_example


class SchemaConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")

    @conformance("C-SCHEMA-001")
    def test_all_schemas_are_valid_draft_2020_12(self) -> None:
        self.catalog.check_all()

    @conformance("C-SCHEMA-002")
    def test_all_examples_validate(self) -> None:
        for path in sorted(EXAMPLES.glob("*.json")):
            name = path.stem
            with self.subTest(example=name):
                with path.open("r", encoding="utf-8") as handle:
                    self.catalog.validate(name, json.load(handle))

    @conformance("C-ID-001")
    def test_identity_is_externalized_and_versioned(self) -> None:
        identity = load_example("identity")
        self.catalog.validate("identity", identity)
        serialized = json.dumps(identity)
        restored = json.loads(serialized)
        self.assertEqual(identity["organism_id"], restored["organism_id"])
        self.assertEqual(identity["immutable_constraints"], restored["immutable_constraints"])

    @conformance("C-GOV-001")
    def test_unknown_governance_fields_are_rejected(self) -> None:
        identity = copy.deepcopy(load_example("identity"))
        identity["model_generated_permission"] = "allow_all"
        with self.assertRaises(ANOError) as raised:
            self.catalog.validate("identity", identity)
        self.assertEqual("SCHEMA_INVALID", raised.exception.code)

    @conformance("C-CTX-001")
    def test_decision_context_contains_required_versions(self) -> None:
        snapshot = load_example("decision-context-snapshot")
        self.catalog.validate("decision-context-snapshot", snapshot)
        self.assertTrue(snapshot["state_versions"])
        self.assertTrue(snapshot["policy_versions"])
        self.assertTrue(snapshot["model_revision"])


if __name__ == "__main__":
    unittest.main()

