from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ano_runtime import (
    ANOError, CapabilityPackageSigner, CapabilityPackageVerifier,
    FederatedBudgetGrantVerifier, FederationBundleSigner, FederationBundleVerifier,
    FederationViewReconciler, LearningWithdrawalReconciler, LearningWithdrawalSigner,
    LearningWithdrawalVerifier, NodeSloReportSigner, SchemaCatalog,
    SqliteFederatedBudgetAuthority, SqliteFederatedLineageNode, SqliteFederatedNode,
    SqliteFederatedSloController, sha256_json,
)

from tests.support import STANDARD_ROOT, conformance


class FederatedGrowthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.5.0")
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.package_signer = CapabilityPackageSigner(
            self.catalog, "https://release.ano.test", "release_key_001",
        )
        self.package_verifier = CapabilityPackageVerifier(
            self.catalog, trusted_issuers={"https://release.ano.test"},
            trusted_keys={"release_key_001": self.package_signer.public_key},
        )
        self.bundle_signer = FederationBundleSigner(
            self.catalog, "federation_alpha", "https://federation.ano.test", "federation_key_001",
        )
        self.bundle_verifier = FederationBundleVerifier(
            self.catalog, self.package_verifier, federation_id="federation_alpha",
            trusted_issuers={"https://federation.ano.test"},
            trusted_keys={"federation_key_001": self.bundle_signer.public_key},
        )

    @staticmethod
    def policy(version: int = 1) -> dict:
        return {
            "policy_id": "federation_policy_alpha", "version": version,
            "allowed_node_ids": ["node_alpha", "node_beta", "node_gamma"],
            "minimum_view_quorum": 2, "global_budget_limits": {"model_tokens": 100},
            "tenant_budget_limits": {
                "tenant_alpha": {"model_tokens": 60}, "tenant_beta": {"model_tokens": 80},
            },
            "slo_minimum_nodes": 2,
            "slo_targets": {
                "tenant_alpha:runtime_api": {"availability_target": 0.99, "p95_latency_target_ms": 100, "minimum_nodes": 2, "recovery_windows": 2},
            },
            "withdrawal_required": True,
        }

    def package(self, generation: int) -> dict:
        return self.package_signer.create(
            component_id="model_router", generation=generation, kind="orchestration",
            artifact_hash=sha256_json({"artifact": generation}),
            manifest_hash=sha256_json({"manifest": generation}),
            capabilities=["route_models"], required_permissions=["model_invoke"],
            budget_ceiling={"model_tokens": 60}, source_adapter_id=f"model_adapter_{generation:03d}",
            evidence_ids=[f"evidence_model_{generation:03d}"],
            goal_contract_hash=sha256_json({"goal": "route"}), evaluator_hash=sha256_json({"eval": "route"}),
            rollback_package_id=None,
        )

    def bundles(self) -> tuple[dict, dict]:
        first = self.bundle_signer.create(1, self.policy(), [self.package(1)], previous_bundle_hash=None, now=self.now)
        second = self.bundle_signer.create(
            2, self.policy(), [self.package(2)], previous_bundle_hash=first["bundle_hash"],
            now=self.now + timedelta(seconds=1),
        )
        return first, second

    def node(self, path: Path, node_id: str, key_id: str) -> SqliteFederatedNode:
        return SqliteFederatedNode(path, self.catalog, node_id, self.bundle_verifier, key_id)

    @conformance("F-POL-001")
    def test_signed_policy_and_capability_view_reaches_independent_node_quorum(self) -> None:
        first, _ = self.bundles()
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            alpha = self.node(root / "alpha.db", "node_alpha", "node_key_alpha")
            beta = self.node(root / "beta.db", "node_beta", "node_key_beta")
            alpha.apply(first); beta.apply(first)
            reconcile = FederationViewReconciler(
                self.catalog, "federation_alpha", {
                    "node_alpha": ("zone_a", "node_key_alpha", alpha.public_key),
                    "node_beta": ("zone_b", "node_key_beta", beta.public_key),
                }, quorum=2,
            )
            checkpoints = [alpha.checkpoint(now=self.now), beta.checkpoint(now=self.now)]
            view = reconcile.reconcile(checkpoints, minimum_epoch=1)
            self.assertEqual(first["view_hash"], view["view_hash"])
            with self.assertRaises(ANOError) as replay:
                reconcile.reconcile(checkpoints, minimum_epoch=2)
            self.assertEqual("FEDERATION_CHECKPOINT_ROLLBACK", replay.exception.code)
            tampered = copy.deepcopy(first)
            tampered["policy"]["global_budget_limits"]["model_tokens"] = 1000
            with self.assertRaises(ANOError) as signature:
                self.bundle_verifier.verify(tampered)
            self.assertEqual("FEDERATION_SIGNATURE_INVALID", signature.exception.code)

    @conformance("F-VIEW-001")
    def test_epoch_equivocation_history_gap_and_checkpoint_divergence_fail_closed(self) -> None:
        first, second = self.bundles()
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            alpha = self.node(root / "alpha.db", "node_alpha", "node_key_alpha")
            alpha.apply(first)
            equivocal = self.bundle_signer.create(1, self.policy(2), [self.package(1)], previous_bundle_hash=None, now=self.now)
            with self.assertRaises(ANOError) as equivocation:
                alpha.apply(equivocal)
            self.assertEqual("FEDERATION_EQUIVOCATION", equivocation.exception.code)
            changed_policy = self.policy()
            changed_policy["global_budget_limits"]["model_tokens"] = 99
            policy_rewrite = self.bundle_signer.create(
                2, changed_policy, [self.package(2)], previous_bundle_hash=first["bundle_hash"], now=self.now,
            )
            with self.assertRaises(ANOError) as policy_rollback:
                alpha.apply(policy_rewrite)
            self.assertEqual("FEDERATION_POLICY_ROLLBACK", policy_rollback.exception.code)
            package_rewrite = self.bundle_signer.create(
                2, self.policy(), [self.package(1)], previous_bundle_hash=first["bundle_hash"], now=self.now,
            )
            with self.assertRaises(ANOError) as package_rollback:
                alpha.apply(package_rewrite)
            self.assertEqual("FEDERATION_PACKAGE_ROLLBACK", package_rollback.exception.code)
            empty = self.node(root / "empty.db", "node_beta", "node_key_beta")
            with self.assertRaises(ANOError) as gap:
                empty.apply(second)
            self.assertEqual("FEDERATION_HISTORY_GAP", gap.exception.code)
            beta = self.node(root / "beta.db", "node_beta", "node_key_beta")
            beta.apply(equivocal)
            reconciler = FederationViewReconciler(
                self.catalog, "federation_alpha", {
                    "node_alpha": ("zone_a", "node_key_alpha", alpha.public_key),
                    "node_beta": ("zone_b", "node_key_beta", beta.public_key),
                }, quorum=2,
            )
            with self.assertRaises(ANOError) as diverged:
                reconciler.reconcile([alpha.checkpoint(), beta.checkpoint()], minimum_epoch=1)
            self.assertEqual("FEDERATION_VIEW_DIVERGED", diverged.exception.code)

    @conformance("F-OFF-001")
    def test_offline_node_must_replay_every_signed_epoch_before_joining_current_view(self) -> None:
        first, second = self.bundles()
        with tempfile.TemporaryDirectory() as directory_name:
            node = self.node(Path(directory_name) / "offline.db", "node_gamma", "node_key_gamma")
            with self.assertRaises(ANOError):
                node.apply(second)
            current = node.catch_up([first, second])
            self.assertEqual(2, current["epoch"])
            self.assertEqual(second["bundle_hash"], current["bundle_hash"])

    @conformance("F-BUD-001")
    def test_budget_authority_is_idempotent_and_enforces_global_tenant_and_node_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            authority = SqliteFederatedBudgetAuthority(
                Path(directory_name) / "budget.db", self.catalog, "budget_authority", "budget_key_001",
                sha256_json(self.policy()),
                {"model_tokens": 100}, {"tenant_alpha": {"model_tokens": 60}, "tenant_beta": {"model_tokens": 80}},
            )
            grant = authority.allocate("request_alpha_001", "node_alpha", "tenant_alpha", {"model_tokens": 50}, now=self.now)
            replay = authority.allocate("request_alpha_001", "node_alpha", "tenant_alpha", {"model_tokens": 50}, now=self.now)
            self.assertEqual(grant["allocation_id"], replay["allocation_id"])
            with self.assertRaises(ANOError) as conflict:
                authority.allocate("request_alpha_001", "node_alpha", "tenant_alpha", {"model_tokens": 40}, now=self.now)
            self.assertEqual("FEDERATED_BUDGET_IDEMPOTENCY_CONFLICT", conflict.exception.code)
            with self.assertRaises(ANOError) as tenant_limit:
                authority.allocate("request_alpha_002", "node_beta", "tenant_alpha", {"model_tokens": 20}, now=self.now)
            self.assertEqual("FEDERATED_TENANT_BUDGET_EXCEEDED", tenant_limit.exception.code)
            verifier = FederatedBudgetGrantVerifier(self.catalog, "budget_authority", "budget_key_001", sha256_json(self.policy()), authority.public_key)
            verifier.verify(grant, node_id="node_alpha", tenant_id="tenant_alpha", now=self.now)
            with self.assertRaises(ANOError) as rebound:
                verifier.verify(grant, node_id="node_beta", tenant_id="tenant_alpha", now=self.now)
            self.assertEqual("FEDERATED_BUDGET_BINDING_MISMATCH", rebound.exception.code)

    @conformance("F-BUD-002")
    def test_concurrent_tenants_cannot_overallocate_global_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            authority = SqliteFederatedBudgetAuthority(
                Path(directory_name) / "budget.db", self.catalog, "budget_authority", "budget_key_001",
                sha256_json(self.policy()),
                {"model_tokens": 100}, {"tenant_alpha": {"model_tokens": 80}, "tenant_beta": {"model_tokens": 80}},
            )

            def allocate(item: tuple[str, str, str]) -> str:
                request_id, node_id, tenant_id = item
                try:
                    authority.allocate(request_id, node_id, tenant_id, {"model_tokens": 70}, now=self.now)
                    return "accepted"
                except ANOError as exc:
                    return exc.code

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(allocate, [
                    ("request_concurrent_alpha", "node_alpha", "tenant_alpha"),
                    ("request_concurrent_beta", "node_beta", "tenant_beta"),
                ]))
            self.assertEqual(1, outcomes.count("accepted"))
            self.assertEqual(1, outcomes.count("FEDERATED_GLOBAL_BUDGET_EXCEEDED"))

    def slo_signers(self):
        alpha = NodeSloReportSigner(self.catalog, "node_alpha", "slo_key_alpha")
        beta = NodeSloReportSigner(self.catalog, "node_beta", "slo_key_beta")
        trusted = {
            "node_alpha": ("zone_a", "slo_key_alpha", alpha.public_key),
            "node_beta": ("zone_b", "slo_key_beta", beta.public_key),
        }
        return alpha, beta, trusted

    def slo_reports(self, alpha, beta, sequence: int, successes: int, start: datetime):
        end = start + timedelta(minutes=1)
        return [
            alpha.report("tenant_alpha", "runtime_api", sequence, window_start=start, window_end=end, sample_count=100, success_count=successes, latency_p95_ms=80),
            beta.report("tenant_alpha", "runtime_api", sequence, window_start=start, window_end=end, sample_count=100, success_count=successes, latency_p95_ms=90),
        ]

    @conformance("F-SLO-001")
    def test_signed_multinode_error_budget_degrades_then_requires_stable_recovery(self) -> None:
        alpha, beta, trusted = self.slo_signers()
        with tempfile.TemporaryDirectory() as directory_name:
            controller = SqliteFederatedSloController(
                Path(directory_name) / "slo.db", self.catalog, trusted,
                policy_hash=sha256_json(self.policy()), targets=self.policy()["slo_targets"],
            )
            violated = controller.evaluate(
                "tenant_alpha", "runtime_api", self.slo_reports(alpha, beta, 1, 95, self.now),
                now=self.now + timedelta(minutes=1),
            )
            self.assertEqual(("violated", "degraded", "degrade"), (violated["status"], violated["operating_mode"], violated["action"]))
            hold = controller.evaluate(
                "tenant_alpha", "runtime_api", self.slo_reports(alpha, beta, 2, 100, self.now + timedelta(minutes=1)),
                now=self.now + timedelta(minutes=2),
            )
            self.assertEqual(("degraded", "hold"), (hold["operating_mode"], hold["action"]))
            recovered = controller.evaluate(
                "tenant_alpha", "runtime_api", self.slo_reports(alpha, beta, 3, 100, self.now + timedelta(minutes=2)),
                now=self.now + timedelta(minutes=3),
            )
            self.assertEqual(("normal", "recover"), (recovered["operating_mode"], recovered["action"]))

    @conformance("F-SLO-002")
    def test_missing_forged_or_replayed_slo_evidence_cannot_trigger_normal_mode(self) -> None:
        alpha, beta, trusted = self.slo_signers()
        reports = self.slo_reports(alpha, beta, 1, 100, self.now)
        with tempfile.TemporaryDirectory() as directory_name:
            controller = SqliteFederatedSloController(
                Path(directory_name) / "slo.db", self.catalog, trusted,
                policy_hash=sha256_json(self.policy()), targets=self.policy()["slo_targets"],
            )
            unknown = controller.evaluate(
                "tenant_alpha", "runtime_api", reports[:1], now=self.now + timedelta(minutes=1),
            )
            self.assertEqual(("unknown", "degraded", "safe_degrade"), (unknown["status"], unknown["operating_mode"], unknown["action"]))
            controller = SqliteFederatedSloController(
                Path(directory_name) / "slo-attacks.db", self.catalog, trusted,
                policy_hash=sha256_json(self.policy()), targets=self.policy()["slo_targets"],
            )
            forged = copy.deepcopy(reports[1]); forged["success_count"] = 0
            with self.assertRaises(ANOError) as signature:
                controller.evaluate("tenant_alpha", "runtime_api", [reports[0], forged])
            self.assertEqual("FEDERATED_SLO_SIGNATURE_INVALID", signature.exception.code)
            controller.evaluate("tenant_alpha", "runtime_api", reports)
            with self.assertRaises(ANOError) as replay:
                controller.evaluate("tenant_alpha", "runtime_api", reports)
            self.assertEqual("FEDERATED_SLO_REPLAY", replay.exception.code)
            same_window = self.slo_reports(alpha, beta, 2, 100, self.now)
            with self.assertRaises(ANOError) as window_replay:
                controller.evaluate("tenant_alpha", "runtime_api", same_window)
            self.assertEqual("FEDERATED_SLO_WINDOW_REPLAY", window_replay.exception.code)

    def withdrawal_setup(self, root: Path):
        policy_hash = sha256_json(self.policy())
        signer = LearningWithdrawalSigner(
            self.catalog, "https://learning.ano.test", "learning_key_001", "federation_alpha", policy_hash,
        )
        verifier = LearningWithdrawalVerifier(
            self.catalog, {"https://learning.ano.test"}, {"learning_key_001": signer.public_key},
            federation_id="federation_alpha", policy_hash=policy_hash,
        )
        alpha = SqliteFederatedLineageNode(root / "lineage-alpha.db", self.catalog, "node_alpha", verifier, "lineage_key_alpha")
        beta = SqliteFederatedLineageNode(root / "lineage-beta.db", self.catalog, "node_beta", verifier, "lineage_key_beta")
        reconciler = LearningWithdrawalReconciler(self.catalog, {
            "node_alpha": ("lineage_key_alpha", alpha.public_key),
            "node_beta": ("lineage_key_beta", beta.public_key),
        })
        return signer, alpha, beta, reconciler

    @conformance("F-LRN-001")
    def test_signed_source_withdrawal_invalidates_assets_on_every_required_node(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            signer, alpha, beta, reconciler = self.withdrawal_setup(Path(directory_name))
            alpha.register_asset("source_alpha", "memory_alpha", "memory")
            beta.register_asset("source_alpha", "skill_beta", "skill")
            event = signer.create(
                "source_alpha", 2, {"node_alpha": ["memory_alpha"], "node_beta": ["skill_beta"]},
                reason="consent withdrawn", malicious=False, now=self.now,
            )
            result = reconciler.reconcile(event, [alpha.apply(event), beta.apply(event)])
            self.assertEqual("complete", result["status"])
            self.assertEqual("invalidated", alpha.asset_status("memory_alpha"))
            self.assertEqual("invalidated", beta.asset_status("skill_beta"))

    @conformance("F-LRN-002")
    def test_incomplete_forged_and_stale_withdrawal_propagation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            signer, alpha, beta, reconciler = self.withdrawal_setup(Path(directory_name))
            alpha.register_asset("source_alpha", "memory_alpha", "memory")
            event = signer.create(
                "source_alpha", 2, {"node_alpha": ["memory_alpha"], "node_beta": ["skill_beta"]},
                reason="malicious source", malicious=True, now=self.now,
            )
            alpha_receipt, incomplete = alpha.apply(event), beta.apply(event)
            self.assertEqual("incomplete", incomplete["status"])
            with self.assertRaises(ANOError) as missing:
                reconciler.reconcile(event, [alpha_receipt, incomplete])
            self.assertEqual("LEARNING_PROPAGATION_INCOMPLETE", missing.exception.code)
            beta.register_asset("source_alpha", "skill_beta", "skill")
            self.assertEqual("invalidated", beta.asset_status("skill_beta"))
            complete = beta.apply(event)
            reconciler.reconcile(event, [alpha_receipt, complete])
            forged = copy.deepcopy(complete); forged["invalidated_asset_ids"] = []
            with self.assertRaises(ANOError) as signature:
                reconciler.reconcile(event, [alpha_receipt, forged])
            self.assertEqual("LEARNING_RECEIPT_SIGNATURE_INVALID", signature.exception.code)
            stale = signer.create(
                "source_alpha", 1, {"node_alpha": ["memory_alpha"], "node_beta": ["skill_beta"]},
                reason="stale withdrawal", malicious=False, now=self.now,
            )
            with self.assertRaises(ANOError) as rollback:
                alpha.apply(stale)
            self.assertEqual("LEARNING_WITHDRAWAL_STALE", rollback.exception.code)

    @conformance("F-E2E-001")
    def test_one_command_federation_demo_emits_machine_valid_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            output = Path(directory_name) / "federation-acceptance.json"
            completed = subprocess.run(
                [sys.executable, str(STANDARD_ROOT / "tools" / "run_v050_federation_demo.py"), "--output", str(output)],
                cwd=STANDARD_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.catalog.validate("federation-acceptance-report", report)
            self.assertEqual("passed", report["status"])
            self.assertEqual(15, len(report["checks"]))
            self.assertFalse(report["network_runtime_verified"])


if __name__ == "__main__":
    unittest.main()
