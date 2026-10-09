from __future__ import annotations

import copy
import unittest

from ano_runtime import ModelRegistry, SchemaCatalog

from tests.support import STANDARD_ROOT, conformance, load_example


class ModelIndependenceConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")

    @conformance("C-MOD-001")
    def test_model_switch_preserves_external_identity_and_state(self) -> None:
        identity = load_example("identity")
        state = load_example("state-projection")
        first = load_example("model-adapter")
        second = copy.deepcopy(first)
        second["adapter_id"] = "adapter_demo_002"
        second["model_id"] = "stronger-model"
        second["model_revision"] = "2"
        second["status"] = "approved"

        registry = ModelRegistry(lambda value: self.catalog.validate("model-adapter", value))
        registry.register(first)
        registry.register(second)
        registry.activate(second["adapter_id"])

        self.assertEqual("ano_demo_001", identity["organism_id"])
        self.assertEqual(1, state["version"])
        self.assertEqual("adapter_demo_002", registry.active()["adapter_id"])

    @conformance("C-MOD-002")
    def test_model_failure_selects_approved_fallback_or_none(self) -> None:
        active = load_example("model-adapter")
        fallback = copy.deepcopy(active)
        fallback["adapter_id"] = "adapter_demo_fallback"
        fallback["model_id"] = "fallback-model"
        fallback["status"] = "approved"

        registry = ModelRegistry(lambda value: self.catalog.validate("model-adapter", value))
        registry.register(active)
        registry.register(fallback)
        selected = registry.degrade_active()
        self.assertEqual("adapter_demo_fallback", selected["adapter_id"])

        only_active = ModelRegistry(lambda value: self.catalog.validate("model-adapter", value))
        only_active.register(active)
        self.assertIsNone(only_active.degrade_active())

    @conformance("C-UNIT-001")
    @unittest.skip("conditional: reference runtime exposes no physical or financial action profile")
    def test_high_impact_domain_values_require_units(self) -> None:
        pass


if __name__ == "__main__":
    unittest.main()

