from __future__ import annotations

import copy
import unittest

from ano_runtime import (
    ANOError, GoalIntegrityGuard, LearningLineage, ModelAdvancementManager,
    PolicyEvaluationGate, ReflectionEngine, SchemaCatalog, SealedEvaluationSuite,
    SkillRegistry, sha256_json,
)

from tests.support import STANDARD_ROOT, conformance


class AdaptiveProfileConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")
        cls.skill_machine = STANDARD_ROOT / "state-machines" / "v0.3.0" / "skill.machine.json"

    @staticmethod
    def source(*, consent_ref: str | None = "consent_demo", contamination: str = "low") -> dict:
        return {
            "source_id": "source_demo_001", "schema_version": "0.3.0", "source_type": "conversation",
            "license": "principal_authorized", "time_range": "2026-08-27", "selection_rule": "explicit_correction_only",
            "synthetic": False, "sensitivity": "confidential", "consent_ref": consent_ref,
            "contamination_risk": contamination, "derived_asset_ids": [], "status": "active",
        }

    @staticmethod
    def skill(version: str, *, rollback_version: str | None = None) -> dict:
        return {
            "skill_id": "skill_weekly_review", "schema_version": "0.3.0", "version": version,
            "inputs_schema_ref": "schema://weekly-review/input/1.0", "outputs_schema_ref": "schema://weekly-review/output/1.0",
            "required_tools": ["sheets.read", "docs.write"], "required_permissions": ["read_metrics", "write_draft"],
            "side_effects": ["persistent_document_write"], "risk_level": "low", "eval_suite_id": "eval_weekly_review",
            "artifact_hash": sha256_json({"skill": "weekly_review", "version": version}), "source_ids": ["source_demo_001"],
            "approval_ids": [], "monitoring_policy_id": "monitor_skill_standard", "rollback_version": rollback_version,
            "status": "candidate",
        }

    def promote_skill(self, registry: SkillRegistry, version: str) -> None:
        registry.advance("skill_weekly_review", version, "skill.sandboxed", {"artifact_verified", "permissions_declared"})
        registry.advance("skill_weekly_review", version, "skill.tested", {"functional_tests_passed"})
        registry.advance("skill_weekly_review", version, "skill.evaluated", {"sealed_evals_passed", "guardrails_passed"})
        registry.advance("skill_weekly_review", version, "skill.approved", {"independent_approval"})
        registry.advance("skill_weekly_review", version, "skill.staged", {"canary_scope_bounded", "rollback_rehearsed"})
        registry.advance("skill_weekly_review", version, "skill.promoted", {"canary_metrics_passed"})
        registry.advance("skill_weekly_review", version, "skill.monitored", {"monitoring_active"})

    @conformance("A-REF-001")
    def test_reflection_creates_candidate_proposal_without_mutating_production(self) -> None:
        production_policy = {"version": 7, "threshold": 0.8}
        before = copy.deepcopy(production_policy)
        engine = ReflectionEngine(self.catalog)
        reflection, proposal = engine.reflect(
            run_id="run_demo_001", subject_ids=["act_demo_001"], expected="delivered", observed="accepted",
            root_cause="observability_gap", lesson="require delivery verification", source_event_ids=["evt_demo_001"],
            update_type="policy", target_id="policy_delivery", baseline=production_policy,
        )
        self.assertEqual(before, production_policy)
        self.assertEqual("proposal_generated", reflection["status"])
        self.assertEqual("proposed", proposal["status"])
        self.assertEqual(sha256_json(before), proposal["baseline_hash"])

    @conformance("A-MEM-001")
    def test_sensitive_source_without_learning_consent_cannot_enter_long_term_memory(self) -> None:
        lineage = LearningLineage(self.catalog)
        lineage.register_source(self.source(consent_ref=None))
        with self.assertRaises(ANOError) as raised:
            lineage.authorize_memory_write("source_demo_001")
        self.assertEqual("LEARNING_CONSENT_REQUIRED", raised.exception.code)

    @conformance("A-POL-001")
    def test_candidate_policy_passes_signed_baseline_safety_and_cost_gates(self) -> None:
        suite = SealedEvaluationSuite(
            self.catalog, suite_id="eval_policy_regression", holdout=[
                {"input": {"risk": "high"}, "expected": "deny"},
                {"input": {"risk": "low"}, "expected": "allow"},
            ], minimum_accuracy=1.0, maximum_cost_delta=0.1, baseline={"policy_version": 7},
        )
        report = suite.evaluate("policy_candidate_8", lambda item: "deny" if item["risk"] == "high" else "allow", cost_delta=0.05)
        PolicyEvaluationGate().approve(report)
        self.assertEqual("passed", report["status"])
        failed = suite.evaluate("policy_candidate_expensive", lambda item: "deny" if item["risk"] == "high" else "allow", cost_delta=0.5)
        with self.assertRaises(ANOError):
            PolicyEvaluationGate().approve(failed)

    @conformance("A-SKL-001")
    def test_skill_lifecycle_keeps_artifact_permission_eval_approval_and_monitoring_chain(self) -> None:
        registry = SkillRegistry(self.catalog, self.skill_machine)
        skill = self.skill("1.0.0")
        skill["approval_ids"] = ["approval_skill_001"]
        registry.register(skill, behavior=lambda payload: {"summary": payload}, state={"template": "v1"})
        self.promote_skill(registry, "1.0.0")
        stored = registry.skills[("skill_weekly_review", "1.0.0")]
        self.assertTrue(stored["artifact_hash"])
        self.assertTrue(stored["required_permissions"])
        self.assertTrue(stored["eval_suite_id"])
        self.assertTrue(stored["approval_ids"])
        self.assertEqual("monitored", stored["status"])
        self.assertEqual(["candidate", "sandbox", "tested", "evaluated", "approved", "staged", "production", "monitored"], registry.history[("skill_weekly_review", "1.0.0")])

    @conformance("A-RBK-001")
    def test_skill_regression_rolls_behavior_and_state_back_to_signed_baseline(self) -> None:
        registry = SkillRegistry(self.catalog, self.skill_machine)
        v1 = self.skill("1.0.0")
        v1["approval_ids"] = ["approval_v1"]
        registry.register(v1, behavior=lambda _payload: "stable-v1", state={"counter": 1})
        self.promote_skill(registry, "1.0.0")
        v2 = self.skill("2.0.0", rollback_version="1.0.0")
        v2["approval_ids"] = ["approval_v2"]
        registry.register(v2, behavior=lambda _payload: "regressed-v2", state={"counter": 999})
        self.promote_skill(registry, "2.0.0")
        self.assertEqual(("regressed-v2", {"counter": 999}), registry.execute("skill_weekly_review", {}))
        self.assertEqual("1.0.0", registry.rollback("skill_weekly_review", "2.0.0"))
        self.assertEqual(("stable-v1", {"counter": 1}), registry.execute("skill_weekly_review", {}))

    @conformance("A-MOD-001")
    def test_new_model_capability_is_evaluated_mapped_and_only_generates_candidate_orchestration(self) -> None:
        manager = ModelAdvancementManager(self.catalog, {"long_horizon_tool_use": ["project_planning", "commitment_recovery"]})
        previous = {"adapter_id": "adapter_v1", "capabilities": {"long_horizon_tool_use": 0.2}}
        candidate = {"adapter_id": "adapter_v2", "capabilities": {"long_horizon_tool_use": 0.9}}
        reports = []
        for suite_id in ["ano_core_regression", "permission_boundary"]:
            suite = SealedEvaluationSuite(
                self.catalog, suite_id=suite_id, holdout=[{"input": {"case": 1}, "expected": "pass"}],
                minimum_accuracy=1.0, maximum_cost_delta=0.1, baseline={"adapter": "v1"},
            )
            reports.append(suite.evaluate("adapter_v2", lambda _item: "pass"))
        advancement, graph = manager.discover_and_evaluate(previous, candidate, evaluation_reports=reports)
        self.assertEqual("evaluated", advancement["status"])
        self.assertEqual(["long_horizon_tool_use"], advancement["discovered_capabilities"])
        self.assertEqual({"project_planning", "commitment_recovery"}, set(advancement["affected_system_capabilities"]))
        self.assertTrue(advancement["candidate_orchestration_ids"])
        self.assertTrue(all(manager.orchestrations[item]["status"] == "candidate" for item in advancement["candidate_orchestration_ids"]))
        self.assertTrue(graph["edges"])

    @conformance("A-MOD-002")
    def test_model_leap_reports_architecture_leverage_ratio_and_guardrails(self) -> None:
        manager = ModelAdvancementManager(self.catalog, {})
        metrics = manager.leverage_metrics(
            "madv_demo_001", base_gain=0.20, end_to_end_gain=0.34, unlocked=4,
            improved=12, retired=3, cost_delta=-0.18, safety_regressions=0,
        )
        self.assertAlmostEqual(1.70, metrics["architecture_leverage_ratio"])
        self.assertEqual(0, metrics["safety_regression_count"])
        self.assertGreater(metrics["end_to_end_goal_success_gain"], metrics["base_model_eval_gain"])

    @conformance("A-GOAL-001")
    def test_candidate_cannot_claim_improvement_by_lowering_goal_criteria(self) -> None:
        original = {"success_rate_min": 0.90, "safety_incidents_max": 0}
        guard = GoalIntegrityGuard(original, sha256_json({"evaluator": "goal_eval_v1"}))
        guard.validate_claim(original, sha256_json({"evaluator": "goal_eval_v1"}))
        with self.assertRaises(ANOError) as raised:
            guard.validate_claim({"success_rate_min": 0.50, "safety_incidents_max": 2}, sha256_json({"evaluator": "goal_eval_v1"}))
        self.assertEqual("GOAL_DRIFT", raised.exception.code)

    @conformance("A-DATA-001")
    def test_withdrawn_malicious_source_invalidates_all_derived_asset_types(self) -> None:
        lineage = LearningLineage(self.catalog)
        lineage.register_source(self.source())
        lineage.register_derived("source_demo_001", "mem_derived_001", "memory")
        lineage.register_derived("source_demo_001", "skill_derived_001", "skill")
        lineage.register_derived("source_demo_001", "policy_derived_001", "policy")
        invalidated = lineage.withdraw("source_demo_001", malicious=True)
        self.assertEqual(("mem_derived_001", "policy_derived_001", "skill_derived_001"), invalidated)
        self.assertTrue(all(lineage.assets[item]["status"] == "invalidated" for item in invalidated))
        self.assertEqual("quarantined", lineage.sources["source_demo_001"]["status"])

    @conformance("A-EVAL-001")
    def test_candidate_cannot_read_holdout_answers_or_lower_sealed_threshold(self) -> None:
        suite = SealedEvaluationSuite(
            self.catalog, suite_id="eval_sealed_001",
            holdout=[{"input": {"question": "2+2"}, "expected": 4}],
            minimum_accuracy=1.0, maximum_cost_delta=0.0, baseline={"score": 1.0},
        )
        visible_keys: list[set[str]] = []

        def honest(candidate_input: dict) -> int:
            visible_keys.append(set(candidate_input))
            return 4

        passed = suite.evaluate("candidate_honest", honest)
        self.assertEqual("passed", passed["status"])
        self.assertEqual([{"question"}], visible_keys)

        def tamper(_candidate_input: dict) -> int:
            suite._SealedEvaluationSuite__thresholds["minimum_accuracy"] = 0.0  # type: ignore[attr-defined]
            return 0

        invalid = suite.evaluate("candidate_tamper", tamper)
        self.assertEqual("invalid", invalid["status"])
        self.assertFalse(invalid["guardrails"]["seals_intact"])


if __name__ == "__main__":
    unittest.main()
