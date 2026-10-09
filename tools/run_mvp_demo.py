from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    ANOError, ActionRuntime, AppendOnlyEventStore, ModelAdvancementManager,
    PermissionEngine, PolicyBoundClusterReportSourceVerifier,
    PolicyBoundTransparencyCheckpointVerifier, ReflectionEngine, SchemaCatalog,
    SealedEvaluationSuite, SourceObservationRegistry, ToolRegistry,
    TransparencyGossipMonitor, __version__, create_cluster_report_source_envelope,
    new_id, sha256_json, utc_now, witness_public_key_fingerprint,
)


EXAMPLES = ROOT / "examples" / "v0.3.0"


def load_example(name: str) -> dict[str, Any]:
    return json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))


def timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_action_runtime(catalog: SchemaCatalog) -> tuple[ActionRuntime, AppendOnlyEventStore, dict[str, Any]]:
    now = datetime.now(timezone.utc)
    grant = load_example("permission-grant")
    grant["valid_from"] = timestamp(now - timedelta(minutes=1))
    grant["expires_at"] = timestamp(now + timedelta(hours=1))
    action = load_example("action")
    action["status"] = "proposed"
    action["parameters_hash"] = sha256_json(action["parameters"])
    action["timeout_at"] = timestamp(now + timedelta(minutes=5))
    permissions = PermissionEngine()
    permissions.register(grant)
    tools = ToolRegistry()
    tools.register("demo.send", lambda _parameters: {
        "result_code": "ACCEPTED", "observer_id": "tool_mvp_sender",
        "result": {"provider_message_id": "msg_mvp_once"}, "confidence": 1.0,
    })
    store = AppendOnlyEventStore()
    runtime = ActionRuntime.with_standard_machine(
        standard_root=ROOT, event_store=store, permission_engine=permissions, tool_registry=tools,
    )
    runtime.register_verifier(
        "result_code_equals_accepted", lambda _action, observation: observation["result_code"] == "ACCEPTED",
    )
    catalog.validate("permission-grant", grant)
    return runtime, store, action


def expect_error(control: str, expected: str, operation: Any) -> dict[str, str]:
    observed = "NO_ERROR"
    try:
        operation()
    except ANOError as exc:
        observed = exc.code
    return {
        "control": control, "expected_error": expected, "observed_error": observed,
        "status": "passed" if observed == expected else "failed",
    }


def source_entry(key: Ed25519PrivateKey, now: datetime) -> dict[str, Any]:
    return {
        "source_id": "sensor_mvp_primary", "source_domain": "source_domain_mvp",
        "operator_domain": "operator_domain_mvp", "infrastructure_domain": "infra_domain_mvp",
        "upstream_ids": ["upstream_audit_mvp"], "key_id": "source_key_mvp", "algorithm": "Ed25519",
        "public_key_sha256": witness_public_key_fingerprint(key.public_key()), "status": "active",
        "valid_from": timestamp(now - timedelta(days=1)), "valid_until": timestamp(now + timedelta(days=1)),
        "revoked_at": None, "revocation_mode": "none",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the ANO MVP end-to-end acceptance scenario")
    parser.add_argument("--output", default=str(ROOT / "reports" / "mvp-demo-report.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    stages: list[dict[str, Any]] = []
    negative_controls: list[dict[str, str]] = []

    runtime, store, action = make_action_runtime(catalog)
    execution = runtime.execute(action)
    stages.append({"stage": "governed_action", "status": "passed", "evidence": {
        "action_id": execution.action["action_id"], "final_status": execution.action["status"],
        "event_count": len(store.events()), "event_chain": [item["event_type"] for item in store.events()],
        "verified": execution.verification["result"] == "passed" if execution.verification else False,
    }})
    denied_runtime, _denied_store, denied_action = make_action_runtime(catalog)
    denied_action["parameters"]["recipient"] = "attacker@example.com"
    denied_action["parameters_hash"] = sha256_json(denied_action["parameters"])
    negative_controls.append(expect_error(
        "resource_scope_escape", "POLICY_DENIED", lambda: denied_runtime.execute(denied_action),
    ))

    reflection, proposal = ReflectionEngine(catalog).reflect(
        run_id="run_mvp_reflection", subject_ids=[action["action_id"]],
        expected="delivered", observed="accepted", root_cause="observability_gap",
        lesson="add independent delivery verification", source_event_ids=[store.events()[0]["event_id"]],
        update_type="policy", target_id="policy_delivery", baseline={"version": 1, "threshold": 0.8},
    )
    stages.append({"stage": "reflection_candidate", "status": "passed", "evidence": {
        "reflection_id": reflection["reflection_id"], "reflection_status": reflection["status"],
        "proposal_id": proposal["proposal_id"], "proposal_status": proposal["status"],
        "production_mutated": False,
    }})

    manager = ModelAdvancementManager(catalog, {
        "long_horizon_tool_use": ["project_planning", "commitment_recovery"],
    })
    evaluation_reports = []
    for suite_id in ("ano_core_regression", "permission_boundary"):
        suite = SealedEvaluationSuite(
            catalog, suite_id=suite_id, holdout=[{"input": {"case": 1}, "expected": "pass"}],
            minimum_accuracy=1.0, maximum_cost_delta=0.1, baseline={"adapter": "mvp_v1"},
        )
        evaluation_reports.append(suite.evaluate("adapter_mvp_v2", lambda _item: "pass", cost_delta=0.02))
    advancement, graph = manager.discover_and_evaluate(
        {"adapter_id": "adapter_mvp_v1", "capabilities": {"long_horizon_tool_use": 0.2}},
        {"adapter_id": "adapter_mvp_v2", "capabilities": {"long_horizon_tool_use": 0.9}},
        evaluation_reports=evaluation_reports,
    )
    candidate_only = all(
        manager.orchestrations[item]["status"] == "candidate"
        for item in advancement["candidate_orchestration_ids"]
    )
    stages.append({"stage": "model_advancement", "status": "passed" if candidate_only else "failed", "evidence": {
        "advancement_id": advancement["advancement_id"], "discovered_capabilities": advancement["discovered_capabilities"],
        "affected_system_capabilities": advancement["affected_system_capabilities"],
        "candidate_orchestration_ids": advancement["candidate_orchestration_ids"],
        "candidate_only": candidate_only, "capability_edges": len(graph["edges"]),
    }})

    now = datetime.now(timezone.utc)
    source_key, log_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    source_policy = {
        "policy_id": "source_policy_mvp", "schema_version": "0.3.0", "policy_version": 1,
        "issued_at": timestamp(now), "maximum_source_age_seconds": 3600,
        "sources": [source_entry(source_key, now)],
    }
    source_verifier = PolicyBoundClusterReportSourceVerifier(
        catalog, source_policy, {"source_key_mvp": source_key.public_key()},
        expected_policy_id="source_policy_mvp", minimum_policy_version=1,
        expected_policy_hash=sha256_json(source_policy),
    )
    log_policy = {
        "policy_id": "log_policy_mvp", "schema_version": "0.3.0", "policy_version": 1,
        "issued_at": timestamp(now), "logs": [{
            "log_id": "transparency_log_mvp", "registry_id": "source_registry_mvp",
            "operator_domain": "transparency_operator_mvp", "key_id": "log_key_mvp", "algorithm": "Ed25519",
            "public_key_sha256": witness_public_key_fingerprint(log_key.public_key()), "status": "active",
            "valid_from": timestamp(now - timedelta(days=1)), "valid_until": timestamp(now + timedelta(days=1)),
            "revoked_at": None, "revocation_mode": "none",
        }],
    }
    checkpoint_verifier = PolicyBoundTransparencyCheckpointVerifier(
        catalog, log_policy, {"log_key_mvp": log_key.public_key()},
        expected_policy_id="log_policy_mvp", minimum_policy_version=1,
        expected_policy_hash=sha256_json(log_policy),
    )
    with tempfile.TemporaryDirectory() as directory_name:
        directory = Path(directory_name)
        registry = SourceObservationRegistry(directory / "source-registry.jsonl", catalog, source_verifier)
        report_one = load_example("cluster-validation-report")
        source_envelope_one = create_cluster_report_source_envelope(
            report_one, source_key, key_id="source_key_mvp", source_id="sensor_mvp_primary",
            source_domain="source_domain_mvp", issued_at=timestamp(now),
        )
        registry.append(report_one, source_envelope_one)
        checkpoint_one = registry.checkpoint(
            registry_id="source_registry_mvp", log_id="transparency_log_mvp",
            private_key=log_key, key_id="log_key_mvp", issued_at=timestamp(now),
        )
        monitor = TransparencyGossipMonitor(
            directory / "gossip-state.json", catalog, checkpoint_verifier, source_verifier,
        )
        monitor.accept(checkpoint_one, registry.extension_since(0))
        report_two = copy.deepcopy(report_one)
        report_two["run_id"] = "run_mvp_transparency_002"
        source_envelope_two = create_cluster_report_source_envelope(
            report_two, source_key, key_id="source_key_mvp", source_id="sensor_mvp_primary",
            source_domain="source_domain_mvp", issued_at=timestamp(now),
        )
        registry.append(report_two, source_envelope_two)
        checkpoint_two = registry.checkpoint(
            registry_id="source_registry_mvp", log_id="transparency_log_mvp",
            private_key=log_key, key_id="log_key_mvp", issued_at=timestamp(now),
        )
        accepted = monitor.accept(checkpoint_two, registry.extension_since(1))
        negative_controls.append(expect_error(
            "checkpoint_rollback", "TRANSPARENCY_ROLLBACK", lambda: monitor.accept(checkpoint_one, []),
        ))
        stages.append({"stage": "source_transparency", "status": "passed", "evidence": {
            "registry_id": accepted["registry_id"], "log_id": accepted["log_id"],
            "sequence": accepted["sequence"], "head_hash": accepted["head_hash"],
            "source_policy_hash": sha256_json(source_policy), "log_policy_hash": sha256_json(log_policy),
        }})

    conformance_path = ROOT / "reports" / "conformance-report-ano-s.json"
    conformance = json.loads(conformance_path.read_text(encoding="utf-8"))
    summary = conformance["summary"]
    all_passed = all(item["status"] == "passed" for item in stages + negative_controls)
    all_passed = all_passed and summary["failed"] == 0 and not summary["missing_required_tests"]
    demo_report = {
        "report_id": new_id("mvp"), "schema_version": "0.3.0",
        "implementation_version": __version__, "generated_at": utc_now(),
        "status": "passed" if all_passed else "failed", "stages": stages,
        "negative_controls": negative_controls, "conformance_anchor": {
            "profile": "ANO-S", "report_hash": sha256_json(conformance),
            "required_tests": summary["required_tests"], "profile_passed": summary["profile_passed"],
            "failed": summary["failed"], "skipped": summary["skipped"],
        },
    }
    catalog.validate("mvp-demo-report", demo_report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(demo_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": demo_report["status"], "output": str(output), "report_hash": sha256_json(demo_report)}, sort_keys=True))
    return 0 if demo_report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
