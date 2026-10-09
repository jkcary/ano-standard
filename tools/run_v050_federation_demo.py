from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    ANOError, CapabilityPackageSigner, CapabilityPackageVerifier,
    FederatedBudgetGrantVerifier, FederationBundleSigner, FederationBundleVerifier,
    FederationViewReconciler, LearningWithdrawalReconciler, LearningWithdrawalSigner,
    LearningWithdrawalVerifier, NodeSloReportSigner, SchemaCatalog,
    SqliteFederatedBudgetAuthority, SqliteFederatedLineageNode, SqliteFederatedNode,
    SqliteFederatedSloController, __version__, new_id, sha256_json, utc_now,
)
from run_conformance import implementation_source_hash  # noqa: E402


def run(root: Path, catalog: SchemaCatalog) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "status": "passed" if passed else "failed", "detail": detail})

    now = datetime.now(timezone.utc).replace(microsecond=0)
    package_signer = CapabilityPackageSigner(catalog, "https://release.ano.test", "release_key_001")
    package_verifier = CapabilityPackageVerifier(
        catalog, trusted_issuers={"https://release.ano.test"},
        trusted_keys={"release_key_001": package_signer.public_key},
    )

    def package(generation: int) -> dict[str, Any]:
        return package_signer.create(
            component_id="model_router", generation=generation, kind="orchestration",
            artifact_hash=sha256_json({"artifact": generation}), manifest_hash=sha256_json({"manifest": generation}),
            capabilities=["route_models"], required_permissions=["model_invoke"],
            budget_ceiling={"model_tokens": 60}, source_adapter_id=f"model_adapter_{generation:03d}",
            evidence_ids=[f"evidence_model_{generation:03d}"], goal_contract_hash=sha256_json({"goal": "route"}),
            evaluator_hash=sha256_json({"eval": "route"}), rollback_package_id=None,
        )

    policy = {
        "policy_id": "federation_policy_alpha", "version": 1,
        "allowed_node_ids": ["node_alpha", "node_beta", "node_gamma"], "minimum_view_quorum": 2,
        "global_budget_limits": {"model_tokens": 100},
        "tenant_budget_limits": {"tenant_alpha": {"model_tokens": 60}, "tenant_beta": {"model_tokens": 80}},
        "slo_minimum_nodes": 2,
        "slo_targets": {
            "tenant_alpha:runtime_api": {"availability_target": 0.99, "p95_latency_target_ms": 100, "minimum_nodes": 2, "recovery_windows": 2},
            "tenant_alpha:another_api": {"availability_target": 0.99, "p95_latency_target_ms": 100, "minimum_nodes": 2, "recovery_windows": 2},
        },
        "withdrawal_required": True,
    }
    signer = FederationBundleSigner(catalog, "federation_alpha", "https://federation.ano.test", "federation_key_001")
    verifier = FederationBundleVerifier(
        catalog, package_verifier, federation_id="federation_alpha",
        trusted_issuers={"https://federation.ano.test"}, trusted_keys={"federation_key_001": signer.public_key},
    )
    first = signer.create(1, policy, [package(1)], previous_bundle_hash=None, now=now)
    second = signer.create(2, policy, [package(2)], previous_bundle_hash=first["bundle_hash"], now=now + timedelta(seconds=1))
    verifier.verify(first); verifier.verify(second)
    check("signed_release_chain", second["previous_bundle_hash"] == first["bundle_hash"], "policy and capability packages form a signed hash-linked epoch chain")
    alpha = SqliteFederatedNode(root / "node-alpha.db", catalog, "node_alpha", verifier, "node_key_alpha")
    beta = SqliteFederatedNode(root / "node-beta.db", catalog, "node_beta", verifier, "node_key_beta")
    gamma = SqliteFederatedNode(root / "node-gamma.db", catalog, "node_gamma", verifier, "node_key_gamma")
    observed = "NO_ERROR"
    try:
        gamma.apply(second)
    except ANOError as exc:
        observed = exc.code
    check("history_gap_rejection", observed == "FEDERATION_HISTORY_GAP", f"observed={observed}")
    gamma.catch_up([first, second])
    check("offline_epoch_catchup", gamma.current()["epoch"] == 2, "offline node replayed every missing signed epoch")
    alpha.catch_up([first, second]); beta.catch_up([first, second])
    reconciler = FederationViewReconciler(catalog, "federation_alpha", {
        "node_alpha": ("zone_a", "node_key_alpha", alpha.public_key),
        "node_beta": ("zone_b", "node_key_beta", beta.public_key),
    }, quorum=2)
    consistent = reconciler.reconcile([alpha.checkpoint(now=now), beta.checkpoint(now=now)], minimum_epoch=2)
    check("independent_consistent_view", consistent["view_hash"] == second["view_hash"], "independent failure domains signed one policy/package view")
    equivocal = signer.create(1, {**policy, "version": 2}, [package(1)], previous_bundle_hash=None, now=now)
    observed = "NO_ERROR"
    try:
        alpha.apply(equivocal)
    except ANOError as exc:
        observed = exc.code
    check("epoch_equivocation_rejection", observed == "FEDERATION_EQUIVOCATION", f"observed={observed}")

    authority = SqliteFederatedBudgetAuthority(
        root / "budget.db", catalog, "budget_authority", "budget_key_001",
        sha256_json(policy),
        {"model_tokens": 100}, {"tenant_alpha": {"model_tokens": 60}, "tenant_beta": {"model_tokens": 80}},
    )
    allocation = authority.allocate("request_alpha_001", "node_alpha", "tenant_alpha", {"model_tokens": 50}, now=now)
    allocation_verifier = FederatedBudgetGrantVerifier(catalog, "budget_authority", "budget_key_001", sha256_json(policy), authority.public_key)
    allocation_verifier.verify(allocation, node_id="node_alpha", tenant_id="tenant_alpha", now=now)
    check("signed_budget_allocation", allocation["amounts"]["model_tokens"] == 50, "short-lived allocation is signed and node/tenant bound")
    observed = "NO_ERROR"
    try:
        allocation_verifier.verify(allocation, node_id="node_beta", tenant_id="tenant_alpha", now=now)
    except ANOError as exc:
        observed = exc.code
    check("budget_rebinding_rejection", observed == "FEDERATED_BUDGET_BINDING_MISMATCH", f"observed={observed}")
    observed = "NO_ERROR"
    try:
        authority.allocate("request_alpha_002", "node_beta", "tenant_alpha", {"model_tokens": 20}, now=now)
    except ANOError as exc:
        observed = exc.code
    check("tenant_budget_arbitration", observed == "FEDERATED_TENANT_BUDGET_EXCEEDED", f"observed={observed}")

    slo_alpha = NodeSloReportSigner(catalog, "node_alpha", "slo_key_alpha")
    slo_beta = NodeSloReportSigner(catalog, "node_beta", "slo_key_beta")
    slo = SqliteFederatedSloController(root / "slo.db", catalog, {
        "node_alpha": ("zone_a", "slo_key_alpha", slo_alpha.public_key),
        "node_beta": ("zone_b", "slo_key_beta", slo_beta.public_key),
    }, policy_hash=sha256_json(policy), targets=policy["slo_targets"])

    def reports(sequence: int, successes: int, start: datetime) -> list[dict[str, Any]]:
        end = start + timedelta(minutes=1)
        return [
            slo_alpha.report("tenant_alpha", "runtime_api", sequence, window_start=start, window_end=end, sample_count=100, success_count=successes, latency_p95_ms=80),
            slo_beta.report("tenant_alpha", "runtime_api", sequence, window_start=start, window_end=end, sample_count=100, success_count=successes, latency_p95_ms=90),
        ]

    bad = slo.evaluate("tenant_alpha", "runtime_api", reports(1, 95, now), now=now + timedelta(minutes=1))
    check("error_budget_degrade", bad["action"] == "degrade" and bad["operating_mode"] == "degraded", "excess error-budget burn triggered deterministic degradation")
    hold = slo.evaluate("tenant_alpha", "runtime_api", reports(2, 100, now + timedelta(minutes=1)), now=now + timedelta(minutes=2))
    recovered = slo.evaluate("tenant_alpha", "runtime_api", reports(3, 100, now + timedelta(minutes=2)), now=now + timedelta(minutes=3))
    check("stable_slo_recovery", hold["action"] == "hold" and recovered["action"] == "recover", "two advancing healthy windows were required before recovery")
    missing = slo.evaluate("tenant_alpha", "another_api", [
        slo_alpha.report("tenant_alpha", "another_api", 1, window_start=now, window_end=now + timedelta(minutes=1), sample_count=100, success_count=100, latency_p95_ms=20),
    ], now=now + timedelta(minutes=1))
    check("missing_slo_quorum_safe_degrade", missing["action"] == "safe_degrade", "missing independent node evidence could not assert healthy mode")

    withdrawal_signer = LearningWithdrawalSigner(
        catalog, "https://learning.ano.test", "learning_key_001", "federation_alpha", sha256_json(policy),
    )
    withdrawal_verifier = LearningWithdrawalVerifier(
        catalog, {"https://learning.ano.test"}, {"learning_key_001": withdrawal_signer.public_key},
        federation_id="federation_alpha", policy_hash=sha256_json(policy),
    )
    lineage_alpha = SqliteFederatedLineageNode(root / "lineage-alpha.db", catalog, "node_alpha", withdrawal_verifier, "lineage_key_alpha")
    lineage_beta = SqliteFederatedLineageNode(root / "lineage-beta.db", catalog, "node_beta", withdrawal_verifier, "lineage_key_beta")
    lineage_alpha.register_asset("source_alpha", "memory_alpha", "memory")
    lineage_beta.register_asset("source_alpha", "skill_beta", "skill")
    withdrawal = withdrawal_signer.create("source_alpha", 2, {"node_alpha": ["memory_alpha"], "node_beta": ["skill_beta"]}, reason="consent withdrawn", malicious=False, now=now)
    receipt_alpha, receipt_beta = lineage_alpha.apply(withdrawal), lineage_beta.apply(withdrawal)
    withdrawal_reconciler = LearningWithdrawalReconciler(catalog, {
        "node_alpha": ("lineage_key_alpha", lineage_alpha.public_key),
        "node_beta": ("lineage_key_beta", lineage_beta.public_key),
    })
    propagation = withdrawal_reconciler.reconcile(withdrawal, [receipt_alpha, receipt_beta])
    check("verified_withdrawal_propagation", propagation["status"] == "complete" and len(propagation["invalidated_asset_ids"]) == 2, "all required nodes signed complete derived-asset invalidation")
    forged = copy.deepcopy(receipt_beta); forged["invalidated_asset_ids"] = []
    observed = "NO_ERROR"
    try:
        withdrawal_reconciler.reconcile(withdrawal, [receipt_alpha, forged])
    except ANOError as exc:
        observed = exc.code
    check("forged_withdrawal_receipt_rejection", observed == "LEARNING_RECEIPT_SIGNATURE_INVALID", f"observed={observed}")
    incomplete_event = withdrawal_signer.create("source_beta", 1, {"node_alpha": ["missing_asset"], "node_beta": ["other_missing"]}, reason="source withdrawn", malicious=False, now=now)
    incomplete_alpha = lineage_alpha.apply(incomplete_event); incomplete_beta = lineage_beta.apply(incomplete_event)
    observed = "NO_ERROR"
    try:
        withdrawal_reconciler.reconcile(incomplete_event, [incomplete_alpha, incomplete_beta])
    except ANOError as exc:
        observed = exc.code
    check("incomplete_withdrawal_rejection", observed == "LEARNING_PROPAGATION_INCOMPLETE", f"observed={observed}")
    check("network_runtime_nonclaim", True, "separate node databases prove protocol views, not a real multi-host transport or consensus deployment")
    return {
        "report_id": new_id("far"), "schema_version": "0.5.0", "implementation_version": __version__,
        "implementation_source_hash": implementation_source_hash(), "generated_at": utc_now(),
        "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed", "checks": checks,
        "final_epoch": consistent["epoch"], "consistent_view_hash": consistent["view_hash"],
        "budget_allocation_id": allocation["allocation_id"], "slo_decision_id": recovered["decision_id"],
        "withdrawal_id": withdrawal["withdrawal_id"], "network_runtime_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ANO 0.5 federated growth acceptance")
    parser.add_argument("--output", default=str(ROOT / "reports" / "v050-federation-acceptance.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.5.0")
    with tempfile.TemporaryDirectory() as directory_name:
        report = run(Path(directory_name), catalog)
    catalog.validate("federation-acceptance-report", report)
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "output": str(output)}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
