from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ano_runtime import (
    ANOError,
    CapabilityPackageSigner,
    CapabilityPackageVerifier,
    ModelCapabilityPackageFactory,
    PersistentEvolutionKernel,
    SchemaCatalog,
    sha256_json,
)

from tests.support import STANDARD_ROOT, conformance


class PersistentEvolutionKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.5.0")
        self.signer = CapabilityPackageSigner(
            self.catalog, "https://release.ano.local", "release_key_alpha1",
        )
        self.verifier = CapabilityPackageVerifier(
            self.catalog, trusted_issuers={"https://release.ano.local"},
            trusted_keys={"release_key_alpha1": self.signer.public_key},
        )
        self.goal_hash = sha256_json({"goal": "increase authorized task success", "version": 1})
        self.evaluator_hash = sha256_json({"evaluator": "sealed_evolution_eval", "version": 1})
        self.policy = {
            "model_router": {
                "permission_ceiling": ["read_context", "invoke_tools"],
                "budget_ceiling": {"model_tokens": 10000, "cost_microunits": 500000},
                "minimum_approvals": 2,
            }
        }

    def kernel(self, path: Path) -> PersistentEvolutionKernel:
        return PersistentEvolutionKernel(
            path, self.catalog, self.verifier, component_policies=self.policy,
        )

    def package(
        self, generation: int, *, rollback_package_id: str | None = None,
        permissions: list[str] | None = None, tokens: int = 1000,
    ) -> dict:
        return self.signer.create(
            component_id="model_router", generation=generation, kind="model",
            artifact_hash=sha256_json({"artifact": f"model-router-{generation}"}),
            manifest_hash=sha256_json({"manifest": generation}),
            capabilities=["long_horizon_tool_use", f"generation_{generation}"],
            required_permissions=permissions or ["read_context"],
            budget_ceiling={"model_tokens": tokens, "cost_microunits": 100000},
            source_adapter_id=f"adapter_model_{generation}", evidence_ids=[f"evidence_model_{generation}"],
            goal_contract_hash=self.goal_hash, evaluator_hash=self.evaluator_hash,
            rollback_package_id=rollback_package_id,
        )

    def advance_to_staged(self, kernel: PersistentEvolutionKernel, transaction: dict) -> dict:
        transaction = kernel.record_evaluation(
            transaction["transaction_id"], report_ids=[f"report_{transaction['transaction_id']}"],
            passed=True, goal_contract_hash=self.goal_hash, evaluator_hash=self.evaluator_hash,
        )
        transaction = kernel.approve(transaction["transaction_id"], [
            {"approval_id": f"approval_security_{transaction['transaction_id']}", "approver_id": "approver_security"},
            {"approval_id": f"approval_owner_{transaction['transaction_id']}", "approver_id": "approver_owner"},
        ])
        return kernel.stage(transaction["transaction_id"])

    def activate_initial(self, kernel: PersistentEvolutionKernel, package: dict) -> dict:
        kernel.register_package(package)
        transaction = kernel.propose(package["package_id"], expected_active_package_id=None)
        transaction = self.advance_to_staged(kernel, transaction)
        return kernel.activate(transaction["transaction_id"])

    @conformance("V-SCH-001")
    def test_v050_schema_catalog_is_complete_and_valid(self) -> None:
        self.catalog.check_all()
        directory = STANDARD_ROOT / "schemas" / "v0.5.0"
        catalog = json.loads((directory / "catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(catalog["schemas"]), sorted(path.name for path in directory.glob("*.schema.json")),
        )

    @conformance("V-PKG-001")
    def test_package_signature_generation_permissions_and_budget_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            kernel = self.kernel(Path(directory_name) / "evolution.db")
            first = self.package(1)
            self.verifier.verify(first)
            changed = copy.deepcopy(first)
            changed["capabilities"].append("forged_capability")
            with self.assertRaises(ANOError) as signature:
                self.verifier.verify(changed)
            self.assertEqual("CAPABILITY_PACKAGE_HASH_INVALID", signature.exception.code)
            kernel.register_package(first)

            permission_expansion = self.package(
                2, rollback_package_id=first["package_id"],
                permissions=["read_context", "admin_control"],
            )
            with self.assertRaises(ANOError) as permission:
                kernel.register_package(permission_expansion)
            self.assertEqual("EVOLUTION_PERMISSION_EXPANSION", permission.exception.code)
            budget_expansion = self.package(2, rollback_package_id=first["package_id"], tokens=10001)
            with self.assertRaises(ANOError) as budget:
                kernel.register_package(budget_expansion)
            self.assertEqual("EVOLUTION_BUDGET_EXPANSION", budget.exception.code)
            same_generation = self.package(1)
            with self.assertRaises(ANOError) as generation:
                kernel.register_package(same_generation)
            self.assertEqual("EVOLUTION_GENERATION_CONFLICT", generation.exception.code)

    @conformance("V-EVO-001")
    def test_evaluation_approval_stage_and_activation_order_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            kernel = self.kernel(Path(directory_name) / "evolution.db")
            package = self.package(1)
            kernel.register_package(package)
            transaction = kernel.propose(package["package_id"], expected_active_package_id=None)
            with self.assertRaises(ANOError) as early_stage:
                kernel.stage(transaction["transaction_id"])
            self.assertEqual("EVOLUTION_STATE_INVALID", early_stage.exception.code)
            with self.assertRaises(ANOError) as goal_drift:
                kernel.record_evaluation(
                    transaction["transaction_id"], report_ids=["report_drift"], passed=True,
                    goal_contract_hash=sha256_json({"goal": "easier"}), evaluator_hash=self.evaluator_hash,
                )
            self.assertEqual("EVOLUTION_EVALUATION_BINDING_INVALID", goal_drift.exception.code)
            evaluated = kernel.record_evaluation(
                transaction["transaction_id"], report_ids=["report_valid"], passed=True,
                goal_contract_hash=self.goal_hash, evaluator_hash=self.evaluator_hash,
            )
            with self.assertRaises(ANOError) as collusion:
                kernel.approve(evaluated["transaction_id"], [
                    {"approval_id": "approval_one", "approver_id": "approver_same"},
                    {"approval_id": "approval_two", "approver_id": "approver_same"},
                ])
            self.assertEqual("EVOLUTION_APPROVAL_INSUFFICIENT", collusion.exception.code)
            approved = kernel.approve(evaluated["transaction_id"], [
                {"approval_id": "approval_security", "approver_id": "approver_security"},
                {"approval_id": "approval_owner", "approver_id": "approver_owner"},
            ])
            staged = kernel.stage(approved["transaction_id"])
            active = kernel.activate(staged["transaction_id"])
            self.assertEqual("active", active["status"])
            self.assertEqual(package["package_id"], kernel.active_package("model_router")["package_id"])
            kernel.verify_log("model_router", expected_head_hash=kernel.head_hash("model_router"))

    @conformance("V-REC-001")
    def test_restart_preserves_staged_transaction_without_auto_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "evolution.db"
            first = self.kernel(path)
            package = self.package(1)
            first.register_package(package)
            staged = self.advance_to_staged(
                first, first.propose(package["package_id"], expected_active_package_id=None),
            )
            restarted = self.kernel(path)
            self.assertIsNone(restarted.active_package("model_router"))
            recovered = restarted.recover_incomplete()
            self.assertEqual(1, len(recovered))
            self.assertEqual("staged", recovered[0]["status"])
            restarted.activate(staged["transaction_id"])
            self.assertEqual(package["package_id"], restarted.active_package("model_router")["package_id"])

    @conformance("V-INT-001")
    def test_transaction_projection_is_rebound_to_package_and_latest_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "evolution.db"
            kernel = self.kernel(path)
            package = self.package(1)
            kernel.register_package(package)
            transaction = kernel.propose(package["package_id"], expected_active_package_id=None)
            evaluated = kernel.record_evaluation(
                transaction["transaction_id"], report_ids=["report_integrity"], passed=True,
                goal_contract_hash=self.goal_hash, evaluator_hash=self.evaluator_hash,
            )
            approved = kernel.approve(evaluated["transaction_id"], [
                {"approval_id": "approval_integrity_a", "approver_id": "approver_security"},
                {"approval_id": "approval_integrity_b", "approver_id": "approver_owner"},
            ])
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE evolution_transactions SET approver_ids_json = ? WHERE transaction_id = ?",
                    ('["approver_attacker","approver_owner"]', approved["transaction_id"]),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ANOError) as corrupt:
                kernel.stage(approved["transaction_id"])
            self.assertEqual("EVOLUTION_TRANSACTION_CORRUPT", corrupt.exception.code)

    @conformance("V-FEN-001")
    def test_competing_upgrades_commit_at_most_one_active_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            kernel = self.kernel(Path(directory_name) / "evolution.db")
            baseline = self.package(1)
            self.activate_initial(kernel, baseline)
            second = self.package(2, rollback_package_id=baseline["package_id"])
            third = self.package(3, rollback_package_id=baseline["package_id"])
            kernel.register_package(second)
            kernel.register_package(third)
            second_tx = self.advance_to_staged(
                kernel, kernel.propose(second["package_id"], expected_active_package_id=baseline["package_id"]),
            )
            third_tx = self.advance_to_staged(
                kernel, kernel.propose(third["package_id"], expected_active_package_id=baseline["package_id"]),
            )
            kernel.activate(second_tx["transaction_id"])
            with self.assertRaises(ANOError) as fenced:
                kernel.activate(third_tx["transaction_id"])
            self.assertEqual("EVOLUTION_FENCED", fenced.exception.code)
            self.assertEqual(second["package_id"], kernel.active_package("model_router")["package_id"])

    @conformance("V-RBK-001")
    def test_rollback_restores_signed_baseline_and_log_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "evolution.db"
            kernel = self.kernel(path)
            baseline = self.package(1)
            self.activate_initial(kernel, baseline)
            candidate = self.package(2, rollback_package_id=baseline["package_id"])
            kernel.register_package(candidate)
            transaction = self.advance_to_staged(
                kernel, kernel.propose(candidate["package_id"], expected_active_package_id=baseline["package_id"]),
            )
            active = kernel.activate(transaction["transaction_id"])
            rolled_back = kernel.rollback(active["transaction_id"], reason="canary safety regression")
            self.assertEqual("rolled_back", rolled_back["status"])
            self.assertEqual(baseline["package_id"], kernel.active_package("model_router")["package_id"])
            head = kernel.head_hash("model_router")
            kernel.verify_log("model_router", expected_head_hash=head)
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE evolution_events SET detail_hash = ? WHERE component_id = ? AND sequence = 1",
                    (sha256_json({"tampered": True}), "model_router"),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ANOError) as tampered:
                kernel.verify_log("model_router", expected_head_hash=head)
            self.assertEqual("EVOLUTION_LOG_CORRUPT", tampered.exception.code)

    @conformance("V-MOD-001")
    def test_model_advancement_builds_only_a_candidate_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            kernel = self.kernel(Path(directory_name) / "evolution.db")
            advancement = {
                "advancement_id": "madv_alpha1_001", "candidate_adapter_id": "adapter_frontier_001",
                "discovered_capabilities": ["long_horizon_tool_use", "verified_planning"],
                "status": "evaluated",
            }
            package = ModelCapabilityPackageFactory(self.signer).build(
                advancement, component_id="model_router", generation=1,
                artifact_hash=sha256_json({"adapter": "frontier"}),
                manifest_hash=sha256_json({"routing": "candidate"}),
                required_permissions=["read_context"], budget_ceiling={"model_tokens": 2000},
                goal_contract_hash=self.goal_hash, evaluator_hash=self.evaluator_hash,
                rollback_package_id=None,
            )
            kernel.register_package(package)
            self.assertEqual("model", package["kind"])
            self.assertEqual("adapter_frontier_001", package["source_adapter_id"])
            self.assertIsNone(kernel.active_package("model_router"))
            self.assertEqual((), kernel.recover_incomplete())

    @conformance("V-E2E-001")
    def test_one_command_evolution_demo_emits_machine_valid_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            output = Path(directory_name) / "evolution-acceptance.json"
            completed = subprocess.run(
                [sys.executable, str(STANDARD_ROOT / "tools" / "run_v050_evolution_demo.py"), "--output", str(output)],
                cwd=STANDARD_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.catalog.validate("evolution-acceptance-report", report)
            self.assertEqual("passed", report["status"])
            self.assertGreaterEqual(len(report["checks"]), 10)
            self.assertTrue(all(item["status"] == "passed" for item in report["checks"]))


if __name__ == "__main__":
    unittest.main()
