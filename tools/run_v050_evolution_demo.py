from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    ANOError, CapabilityPackageSigner, CapabilityPackageVerifier,
    ModelCapabilityPackageFactory, PersistentEvolutionKernel, SchemaCatalog,
    __version__, new_id, sha256_json, utc_now,
)
from run_conformance import implementation_source_hash  # noqa: E402


def run(path: Path, catalog: SchemaCatalog) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "status": "passed" if passed else "failed", "detail": detail})

    signer = CapabilityPackageSigner(catalog, "https://release.ano.local", "release_key_alpha1")
    verifier = CapabilityPackageVerifier(
        catalog, trusted_issuers={"https://release.ano.local"},
        trusted_keys={"release_key_alpha1": signer.public_key},
    )
    policy = {
        "model_router": {
            "permission_ceiling": ["read_context", "invoke_tools"],
            "budget_ceiling": {"model_tokens": 10000, "cost_microunits": 500000},
            "minimum_approvals": 2,
        }
    }
    kernel = PersistentEvolutionKernel(path, catalog, verifier, component_policies=policy)
    goal_hash = sha256_json({"goal": "authorized task success", "version": 1})
    evaluator_hash = sha256_json({"evaluator": "sealed_alpha1", "version": 1})

    def evaluate_approve_stage(transaction: dict[str, Any], suffix: str) -> dict[str, Any]:
        evaluated = kernel.record_evaluation(
            transaction["transaction_id"], report_ids=[f"report_{suffix}"], passed=True,
            goal_contract_hash=goal_hash, evaluator_hash=evaluator_hash,
        )
        approved = kernel.approve(evaluated["transaction_id"], [
            {"approval_id": f"approval_security_{suffix}", "approver_id": "approver_security"},
            {"approval_id": f"approval_owner_{suffix}", "approver_id": "approver_owner"},
        ])
        return kernel.stage(approved["transaction_id"])

    baseline = signer.create(
        component_id="model_router", generation=1, kind="model",
        artifact_hash=sha256_json({"adapter": "stable"}),
        manifest_hash=sha256_json({"routing": "stable"}), capabilities=["bounded_tool_use"],
        required_permissions=["read_context"], budget_ceiling={"model_tokens": 2000},
        source_adapter_id="adapter_stable_001", evidence_ids=["evidence_baseline_001"],
        goal_contract_hash=goal_hash, evaluator_hash=evaluator_hash, rollback_package_id=None,
    )
    kernel.register_package(baseline)
    verifier.verify(baseline)
    check("signed_baseline", True, "baseline package signature and content hash verified")
    baseline_tx = kernel.propose(baseline["package_id"], expected_active_package_id=None)
    baseline_active = kernel.activate(evaluate_approve_stage(baseline_tx, "baseline")["transaction_id"])
    check(
        "governed_baseline_activation",
        baseline_active["status"] == "active" and kernel.active_package("model_router")["package_id"] == baseline["package_id"],
        "initial package passed evaluation, independent approval and staging",
    )

    advancement = {
        "advancement_id": "madv_alpha1_demo", "candidate_adapter_id": "adapter_frontier_001",
        "discovered_capabilities": ["long_horizon_tool_use", "verified_planning"], "status": "evaluated",
    }
    candidate = ModelCapabilityPackageFactory(signer).build(
        advancement, component_id="model_router", generation=2,
        artifact_hash=sha256_json({"adapter": "frontier"}),
        manifest_hash=sha256_json({"routing": "candidate"}),
        required_permissions=["read_context"], budget_ceiling={"model_tokens": 3000},
        goal_contract_hash=goal_hash, evaluator_hash=evaluator_hash,
        rollback_package_id=baseline["package_id"],
    )
    kernel.register_package(candidate)
    check(
        "model_candidate_only", kernel.active_package("model_router")["package_id"] == baseline["package_id"],
        "model advancement registered a candidate without production mutation",
    )
    candidate_tx = kernel.propose(candidate["package_id"], expected_active_package_id=baseline["package_id"])
    observed = "NO_ERROR"
    try:
        kernel.record_evaluation(
            candidate_tx["transaction_id"], report_ids=["report_goal_drift"], passed=True,
            goal_contract_hash=sha256_json({"goal": "lowered"}), evaluator_hash=evaluator_hash,
        )
    except ANOError as exc:
        observed = exc.code
    check("goal_drift_rejected", observed == "EVOLUTION_EVALUATION_BINDING_INVALID", f"observed={observed}")
    evaluated = kernel.record_evaluation(
        candidate_tx["transaction_id"], report_ids=["report_candidate"], passed=True,
        goal_contract_hash=goal_hash, evaluator_hash=evaluator_hash,
    )
    observed = "NO_ERROR"
    try:
        kernel.approve(evaluated["transaction_id"], [
            {"approval_id": "approval_a", "approver_id": "approver_same"},
            {"approval_id": "approval_b", "approver_id": "approver_same"},
        ])
    except ANOError as exc:
        observed = exc.code
    check("approval_collusion_rejected", observed == "EVOLUTION_APPROVAL_INSUFFICIENT", f"observed={observed}")
    approved = kernel.approve(evaluated["transaction_id"], [
        {"approval_id": "approval_candidate_security", "approver_id": "approver_security"},
        {"approval_id": "approval_candidate_owner", "approver_id": "approver_owner"},
    ])
    staged = kernel.stage(approved["transaction_id"])
    restarted = PersistentEvolutionKernel(path, catalog, verifier, component_policies=policy)
    recovered = restarted.recover_incomplete()
    check(
        "restart_no_auto_activation",
        restarted.active_package("model_router")["package_id"] == baseline["package_id"]
        and any(item["transaction_id"] == staged["transaction_id"] and item["status"] == "staged" for item in recovered),
        "staged candidate survived restart but active pointer stayed on baseline",
    )
    active = restarted.activate(staged["transaction_id"])
    check(
        "explicit_atomic_activation",
        active["status"] == "active" and restarted.active_package("model_router")["package_id"] == candidate["package_id"],
        "explicit activation atomically moved transaction and active pointer",
    )
    rolled_back = restarted.rollback(active["transaction_id"], reason="verified canary regression drill")
    restored = restarted.active_package("model_router")
    check(
        "signed_baseline_rollback",
        rolled_back["status"] == "rolled_back" and restored["package_id"] == baseline["package_id"],
        "rollback restored the verified signed baseline",
    )
    head = restarted.head_hash("model_router")
    assert head is not None
    restarted.verify_log("model_router", expected_head_hash=head)
    check("evolution_chain", len(restarted.events("model_router")) >= 10, "component evolution chain is continuous and externally anchorable")

    expanded = signer.create(
        component_id="model_router", generation=3, kind="model",
        artifact_hash=sha256_json({"adapter": "overprivileged"}),
        manifest_hash=sha256_json({"routing": "overprivileged"}), capabilities=["admin_control"],
        required_permissions=["admin_control"], budget_ceiling={"model_tokens": 1000},
        source_adapter_id="adapter_untrusted_scope", evidence_ids=["evidence_scope_attack"],
        goal_contract_hash=goal_hash, evaluator_hash=evaluator_hash,
        rollback_package_id=baseline["package_id"],
    )
    observed = "NO_ERROR"
    try:
        restarted.register_package(expanded)
    except ANOError as exc:
        observed = exc.code
    check("permission_ceiling", observed == "EVOLUTION_PERMISSION_EXPANSION", f"observed={observed}")
    tampered = copy.deepcopy(candidate)
    tampered["budget_ceiling"]["model_tokens"] = 1
    observed = "NO_ERROR"
    try:
        verifier.verify(tampered)
    except ANOError as exc:
        observed = exc.code
    check("package_tamper", observed == "CAPABILITY_PACKAGE_HASH_INVALID", f"observed={observed}")

    return {
        "report_id": new_id("ear"), "schema_version": "0.5.0",
        "implementation_version": __version__, "implementation_source_hash": implementation_source_hash(),
        "generated_at": utc_now(), "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "checks": checks, "component_id": "model_router", "evolution_head_hash": head,
        "restored_package_id": restored["package_id"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the ANO 0.5 persistent evolution-kernel acceptance scenario")
    parser.add_argument("--output", default=str(ROOT / "reports" / "v050-evolution-acceptance.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.5.0")
    with tempfile.TemporaryDirectory() as directory_name:
        report = run(Path(directory_name) / "evolution.db", catalog)
    catalog.validate("evolution-acceptance-report", report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "output": str(output)}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
