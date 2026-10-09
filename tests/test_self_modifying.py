from __future__ import annotations

import copy
import unittest

from ano_runtime import (
    ANOError, CanaryController, ProtectedEvaluationAssets, SchemaCatalog,
    StructuralApprovalGate, StructuralSandbox, sha256_json,
)

from tests.support import STANDARD_ROOT, conformance, load_example


class SelfModifyingProfileConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")
        cls.canary_machine = STANDARD_ROOT / "state-machines" / "v0.3.0" / "canary-deployment.machine.json"

    @staticmethod
    def structural_proposal() -> dict:
        proposal = copy.deepcopy(load_example("change-proposal"))
        proposal["proposal_id"] = "chg_structure_001"
        proposal["proposer_id"] = "agent_architect"
        proposal["change_level"] = "L5_STRUCTURE"
        proposal["target_components"] = ["planner", "agent_topology"]
        proposal["status"] = "proposed"
        return proposal

    @staticmethod
    def scope() -> dict:
        return {
            "identity_ids": ["ano_canary_001"], "traffic_fraction": 0.05,
            "permissions": ["read_metrics", "write_draft"], "data_refs": ["dataset_canary_public"],
            "budget": {"amount": 10, "currency": "USD"},
        }

    @staticmethod
    def guardrails() -> dict:
        return {"minimum_success_rate": 0.90, "maximum_safety_incidents": 0, "maximum_cost": 10}

    def controller(self) -> CanaryController:
        return CanaryController(
            self.catalog, self.canary_machine,
            production_state={"planner": "stable-v1", "routing": {"max_agents": 2}, "policy_version": 7},
        )

    def approval_evidence(self, candidate_state: dict | None = None, scope: dict | None = None) -> dict:
        candidate_state = candidate_state or {"planner": "candidate-v2"}
        scope = scope or self.scope()
        return {
            "approved": True,
            "proposal_id": "chg_structure_001",
            "candidate_hash": sha256_json(candidate_state),
            "scope_hash": sha256_json(scope),
            "expires_at": "2099-01-01T00:00:00Z",
            "proposer_domain": "model_family_architect",
            "independent_domains": ["safety_board", "principal_board"],
            "approved_permissions": ["read_metrics", "write_draft"],
        }

    @conformance("S-SEP-001")
    def test_structural_proposer_cannot_be_sole_approver(self) -> None:
        gate = StructuralApprovalGate(minimum_approvals=2)
        proposal = self.structural_proposal()
        gate.submit(proposal, proposer_domain="model_family_architect")
        with self.assertRaises(ANOError) as proposer:
            gate.approve("chg_structure_001", approver_id="agent_architect", independence_domain="model_family_architect")
        self.assertEqual("SEPARATION_VIOLATION", proposer.exception.code)
        self.assertFalse(gate.approve("chg_structure_001", approver_id="human_safety", independence_domain="safety_board"))
        with self.assertRaises(ANOError):
            gate.approve("chg_structure_001", approver_id="human_safety_2", independence_domain="safety_board")
        self.assertTrue(gate.approve("chg_structure_001", approver_id="human_owner", independence_domain="principal_board"))

    @conformance("S-SBX-001")
    def test_structural_candidate_cannot_access_production_data_credentials_or_network(self) -> None:
        sandbox = StructuralSandbox(self.catalog)
        observed: list[str] = []

        def hostile(view) -> dict:
            observed.append(view.read_input("public_fixture"))
            for operation in [
                lambda: view.read_production("customer_db"),
                lambda: view.get_credential("production_key"),
                lambda: view.network("attacker.example"),
            ]:
                try:
                    operation()
                except ANOError:
                    pass
            return {"result": "attempted"}

        output, record = sandbox.run(
            proposal_id="chg_structure_001", artifact={"code": "candidate"}, candidate=hostile,
            inputs={"public_fixture": "safe", "production_secret": "must_not_mount"},
            allowed_inputs={"public_fixture"}, allowed_outputs={"result"},
        )
        self.assertEqual(["safe"], observed)
        self.assertIsNone(output)
        self.assertEqual("blocked", record["status"])
        self.assertEqual({"production_data", "credential", "network"}, {item["capability"] for item in record["denied_attempts"]})

    @conformance("S-EVAL-001")
    def test_structural_patch_cannot_modify_baseline_thresholds_or_judge(self) -> None:
        assets = ProtectedEvaluationAssets(
            baseline={"success_rate": 0.9}, evaluator={"version": "judge-v1"}, thresholds={"minimum_success": 0.9},
        )
        before = assets.seals
        assets.authorize_patch({"planner": {"strategy": "new-search"}})
        self.assertEqual(before, assets.seals)
        for patch in [
            {"evaluation": {"thresholds": {"minimum_success": 0.1}}},
            {"judge": {"always_pass": True}},
            {"signed_baseline": {"success_rate": 0.1}},
        ]:
            with self.assertRaises(ANOError) as raised:
                assets.authorize_patch(patch)
            self.assertEqual("EVALUATION_ASSET_PROTECTED", raised.exception.code)

    @conformance("S-CAN-001")
    def test_canary_enforces_identity_traffic_permission_data_and_budget_scope(self) -> None:
        controller = self.controller()
        with self.assertRaises(ANOError) as unapproved:
            controller.create(
                proposal_id="chg_structure_001", candidate_state={"planner": "candidate-v2"},
                scope=self.scope(), guardrails=self.guardrails(),
                approval_evidence={
                    "approved": True, "proposer_domain": "model_family_architect",
                    "independent_domains": ["safety_board"],
                    "approved_permissions": ["read_metrics", "write_draft"],
                },
            )
        self.assertEqual("SEPARATION_VIOLATION", unapproved.exception.code)
        controller.create(
            proposal_id="chg_structure_001", candidate_state={"planner": "candidate-v2"},
            scope=self.scope(), guardrails=self.guardrails(), approval_evidence=self.approval_evidence(),
        )
        controller.authorize(
            identity_id="ano_canary_001", traffic_fraction=0.05, permissions={"read_metrics"},
            data_refs={"dataset_canary_public"}, cost=2,
        )
        cases = [
            ({"identity_id": "ano_other", "traffic_fraction": 0.01, "permissions": set(), "data_refs": set(), "cost": 0}, "CANARY_IDENTITY_SCOPE"),
            ({"identity_id": "ano_canary_001", "traffic_fraction": 0.10, "permissions": set(), "data_refs": set(), "cost": 0}, "CANARY_TRAFFIC_SCOPE"),
            ({"identity_id": "ano_canary_001", "traffic_fraction": 0.01, "permissions": {"funds.transfer"}, "data_refs": set(), "cost": 0}, "CANARY_PERMISSION_SCOPE"),
            ({"identity_id": "ano_canary_001", "traffic_fraction": 0.01, "permissions": set(), "data_refs": {"production_private"}, "cost": 0}, "CANARY_DATA_SCOPE"),
            ({"identity_id": "ano_canary_001", "traffic_fraction": 0.01, "permissions": set(), "data_refs": set(), "cost": 9}, "CANARY_BUDGET_SCOPE"),
        ]
        for kwargs, code in cases:
            with self.subTest(code=code), self.assertRaises(ANOError) as raised:
                controller.authorize(**kwargs)
            self.assertEqual(code, raised.exception.code)

    @conformance("S-PRIV-001")
    def test_candidate_cannot_gain_permissions_not_explicitly_approved(self) -> None:
        controller = self.controller()
        escalated_scope = self.scope()
        escalated_scope["permissions"].append("funds.transfer")
        escalated_candidate = {"planner": "candidate-v2", "claimed_permissions": ["funds.transfer"]}
        with self.assertRaises(ANOError) as raised:
            controller.create(
                proposal_id="chg_structure_001",
                candidate_state=escalated_candidate, scope=escalated_scope, guardrails=self.guardrails(),
                approval_evidence=self.approval_evidence(escalated_candidate, escalated_scope),
            )
        self.assertEqual("CANARY_PERMISSION_ESCALATION", raised.exception.code)
        self.assertEqual("stable-v1", controller.current_state["planner"])

        candidate = {"planner": "candidate-v2", "claimed_permissions": ["funds.transfer"]}
        controller.create(
            proposal_id="chg_structure_001",
            candidate_state=candidate, scope=self.scope(), guardrails=self.guardrails(),
            approval_evidence=self.approval_evidence(candidate),
        )
        with self.assertRaises(ANOError) as runtime_denial:
            controller.authorize(
                identity_id="ano_canary_001", traffic_fraction=0.01,
                permissions={"funds.transfer"}, data_refs=set(), cost=0,
            )
        self.assertEqual("CANARY_PERMISSION_SCOPE", runtime_denial.exception.code)

    @conformance("S-RBK-001")
    def test_guardrail_regression_automatically_restores_verified_baseline(self) -> None:
        controller = self.controller()
        baseline = controller.current_state
        candidate = {"planner": "candidate-v2", "routing": {"max_agents": 20}, "policy_version": 7}
        deployment = controller.create(
            proposal_id="chg_structure_001",
            candidate_state=candidate, scope=self.scope(), guardrails=self.guardrails(),
            approval_evidence=self.approval_evidence(candidate),
        )
        status = controller.observe({"success_rate": 0.70, "safety_incidents": 1, "cost": 4})
        self.assertEqual("rolled_back", status)
        self.assertEqual(baseline, controller.current_state)
        self.assertIsNotNone(controller.rollback_record)
        record = controller.rollback_record
        assert record is not None
        self.assertTrue(record["verified"])
        self.assertEqual(deployment["baseline_hash"], record["restored_hash"])
        self.assertEqual(sha256_json(baseline), record["baseline_hash"])
        self.assertEqual({"PERFORMANCE_REGRESSION", "SAFETY_REGRESSION"}, set(record["trigger_codes"]))


if __name__ == "__main__":
    unittest.main()
