from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ano_runtime import (
    ANOError, CanaryController, Ed25519ApprovalEvidenceVerifier,
    KubectlDeploymentProvider, ProductionCanaryOrchestrator, SchemaCatalog,
    SignedTelemetryVerifier, TelemetryCursorStore, sha256_json, sign_ed25519_record, utc_now,
)

from tests.support import STANDARD_ROOT, conformance


class FakeDeploymentProvider:
    def __init__(self) -> None:
        self.rollbacks = 0

    def stage(self, request: dict) -> dict:
        return {
            "receipt_id": "dep_fake_001", "schema_version": "0.3.0",
            "deployment_id": request["deployment_id"], "provider_id": "provider_fake_001",
            "artifact_hash": request["artifact_hash"], "isolation_execution_hash": request["isolation_execution_hash"],
            "external_ref": "fake://candidate", "generation": 1, "created_at": utc_now(), "status": "staged",
        }

    def rollback(self, receipt: dict) -> dict:
        self.rollbacks += 1
        result = copy.deepcopy(receipt)
        result.update({"receipt_id": "dep_fake_rbk", "generation": receipt["generation"] + 1, "created_at": utc_now(), "status": "rolled_back"})
        return result


class FakeTrafficRouter:
    def __init__(self, *, exceed_first_scope: bool = False, fail_on_zero: bool = False) -> None:
        self.fraction = 0.0
        self.requests: list[dict] = []
        self.exceed_first_scope = exceed_first_scope
        self.fail_on_zero = fail_on_zero

    def set_fraction(self, request: dict) -> dict:
        self.requests.append(copy.deepcopy(request))
        requested = float(request["candidate_fraction"])
        if self.fail_on_zero and requested == 0:
            raise RuntimeError("simulated router rollback failure")
        candidate = 0.20 if self.exceed_first_scope and len(self.requests) == 1 else requested
        previous, self.fraction = self.fraction, candidate
        return {
            "route_id": f"rte_fake_{len(self.requests):03d}", "schema_version": "0.3.0",
            "deployment_id": request["deployment_id"], "router_id": "router_fake_001",
            "previous_fraction": previous, "candidate_fraction": candidate,
            "scope_hash": request["scope_hash"], "generation": len(self.requests),
            "updated_at": utc_now(), "status": "rolled_back" if candidate == 0 else "applied",
        }


class ControlPlaneConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")
        cls.machine = STANDARD_ROOT / "state-machines" / "v0.3.0" / "canary-deployment.machine.json"

    def setUp(self) -> None:
        self.approval_private = Ed25519PrivateKey.generate()
        self.telemetry_private = Ed25519PrivateKey.generate()

    @staticmethod
    def scope() -> dict:
        return {
            "identity_ids": ["ano_canary_001"], "traffic_fraction": 0.05,
            "permissions": ["read_metrics"], "data_refs": ["dataset_canary_public"],
            "budget": {"amount": 10, "currency": "USD"},
        }

    @staticmethod
    def guardrails() -> dict:
        return {"minimum_success_rate": 0.90, "maximum_safety_incidents": 0, "maximum_cost": 10}

    def approval(self, candidate: dict, scope: dict) -> dict:
        return sign_ed25519_record({
            "evidence_id": "sev_ed25519_001", "schema_version": "0.3.0", "proposal_id": "chg_structure_001",
            "candidate_hash": sha256_json(candidate), "scope_hash": sha256_json(scope),
            "issued_at": utc_now(), "expires_at": "2099-01-01T00:00:00Z", "proposer_domain": "architecture_domain",
            "approvals": [
                {"approver_id": "human_safety_001", "independence_domain": "safety_board"},
                {"approver_id": "human_owner_001", "independence_domain": "principal_board"},
            ],
            "approved_permissions": ["read_metrics"], "issuer": "approval_service_001", "key_id": "approval_ed_key_001",
        }, self.approval_private)

    def telemetry(self, deployment_id: str, metrics: dict, *, sequence: int = 1, previous_hash: str | None = None) -> dict:
        material = {
            "envelope_id": f"tel_test_{sequence:03d}", "schema_version": "0.3.0", "deployment_id": deployment_id,
            "sequence": sequence, "source_id": "telemetry_service_001", "observed_at": utc_now(),
            "metrics": metrics, "previous_hash": previous_hash, "key_id": "telemetry_ed_key_001",
        }
        material["envelope_hash"] = sha256_json(material)
        return sign_ed25519_record(material, self.telemetry_private)

    def controller(self) -> CanaryController:
        verifier = Ed25519ApprovalEvidenceVerifier(
            self.catalog, {"approval_ed_key_001": self.approval_private.public_key()},
        )
        return CanaryController(
            self.catalog, self.machine, {"planner": "stable-v1"},
            approval_verifier=verifier, require_verified_approval=True,
        )

    @conformance("S-PKI-001")
    def test_ed25519_approval_cannot_be_forged_by_public_key_holder(self) -> None:
        candidate, scope = {"planner": "candidate-v4"}, self.scope()
        evidence = self.approval(candidate, scope)
        verifier = Ed25519ApprovalEvidenceVerifier(
            self.catalog, {"approval_ed_key_001": self.approval_private.public_key()},
        )
        verifier.verify(evidence)
        tampered = copy.deepcopy(evidence)
        tampered["approved_permissions"].append("funds.transfer")
        with self.assertRaises(ANOError) as rejected:
            verifier.verify(tampered)
        self.assertEqual("APPROVAL_SIGNATURE_INVALID", rejected.exception.code)

    @conformance("S-RTEL-001")
    def test_remote_telemetry_rejects_tamper_replay_and_sequence_gap(self) -> None:
        verifier = SignedTelemetryVerifier(
            self.catalog, {"telemetry_ed_key_001": self.telemetry_private.public_key()},
        )
        first = self.telemetry("can_test_001", {"success_rate": 0.95, "safety_incidents": 0, "cost": 1})
        self.assertEqual(0.95, verifier.verify(first, deployment_id="can_test_001")["success_rate"])
        with self.assertRaises(ANOError) as replay:
            verifier.verify(first, deployment_id="can_test_001")
        self.assertEqual("TELEMETRY_REPLAY_OR_GAP", replay.exception.code)
        gap = self.telemetry("can_test_001", {"success_rate": 0.95}, sequence=3, previous_hash=first["envelope_hash"])
        with self.assertRaises(ANOError) as skipped:
            verifier.verify(gap, deployment_id="can_test_001")
        self.assertEqual("TELEMETRY_REPLAY_OR_GAP", skipped.exception.code)
        tampered = self.telemetry("can_other_001", {"success_rate": 0.95})
        tampered["metrics"]["success_rate"] = 0.10
        with self.assertRaises(ANOError) as altered:
            SignedTelemetryVerifier(
                self.catalog, {"telemetry_ed_key_001": self.telemetry_private.public_key()},
            ).verify(tampered, deployment_id="can_other_001")
        self.assertEqual("TELEMETRY_SIGNATURE_INVALID", altered.exception.code)

        with tempfile.TemporaryDirectory() as directory:
            cursor_path = Path(directory) / "telemetry-cursors.json"
            cursor_key = b"test-only-telemetry-cursor-integrity-key"
            persistent = SignedTelemetryVerifier(
                self.catalog, {"telemetry_ed_key_001": self.telemetry_private.public_key()},
                cursor_store=TelemetryCursorStore(cursor_path, self.catalog, key_id="cursor_key_001", key=cursor_key),
            )
            persistent_first = self.telemetry("can_persistent_001", {"success_rate": 0.95})
            persistent.verify(persistent_first, deployment_id="can_persistent_001")
            restarted = SignedTelemetryVerifier(
                self.catalog, {"telemetry_ed_key_001": self.telemetry_private.public_key()},
                cursor_store=TelemetryCursorStore(cursor_path, self.catalog, key_id="cursor_key_001", key=cursor_key),
            )
            with self.assertRaises(ANOError) as restart_replay:
                restarted.verify(persistent_first, deployment_id="can_persistent_001")
            self.assertEqual("TELEMETRY_REPLAY_OR_GAP", restart_replay.exception.code)

    @conformance("S-CTL-001")
    def test_external_canary_compensates_route_and_deployment_on_regression_or_scope_violation(self) -> None:
        candidate, scope = {"planner": "candidate-v4"}, self.scope()
        provider, router = FakeDeploymentProvider(), FakeTrafficRouter()
        orchestrator = ProductionCanaryOrchestrator(
            self.catalog, self.controller(), provider, router,
            SignedTelemetryVerifier(self.catalog, {"telemetry_ed_key_001": self.telemetry_private.public_key()}),
        )
        deployment = orchestrator.stage(
            proposal_id="chg_structure_001", candidate_state=candidate, scope=scope,
            guardrails=self.guardrails(), approval_evidence=self.approval(candidate, scope),
            artifact_ref="registry.example/candidate@sha256:" + "a" * 64,
            artifact_hash="sha256:" + "a" * 64, isolation_execution_hash="sha256:" + "b" * 64,
        )
        status = orchestrator.ingest(self.telemetry(
            deployment["deployment_id"], {"success_rate": 0.5, "safety_incidents": 1, "cost": 1},
        ))
        self.assertEqual("rolled_back", status)
        self.assertEqual(0, router.fraction)
        self.assertEqual(1, provider.rollbacks)
        self.assertEqual("rolled_back", orchestrator.deployment_receipt["status"])

        unsafe_provider, unsafe_router = FakeDeploymentProvider(), FakeTrafficRouter(exceed_first_scope=True)
        unsafe = ProductionCanaryOrchestrator(
            self.catalog, self.controller(), unsafe_provider, unsafe_router,
            SignedTelemetryVerifier(self.catalog, {"telemetry_ed_key_001": self.telemetry_private.public_key()}),
        )
        with self.assertRaises(ANOError) as exceeded:
            unsafe.stage(
                proposal_id="chg_structure_001", candidate_state=candidate, scope=scope,
                guardrails=self.guardrails(), approval_evidence=self.approval(candidate, scope),
                artifact_ref="registry.example/candidate@sha256:" + "a" * 64,
                artifact_hash="sha256:" + "a" * 64, isolation_execution_hash="sha256:" + "b" * 64,
            )
        self.assertEqual("TRAFFIC_SCOPE_VIOLATION", exceeded.exception.code)
        self.assertEqual(0, unsafe_router.fraction)
        self.assertEqual(1, unsafe_provider.rollbacks)

        partial_provider, partial_router = FakeDeploymentProvider(), FakeTrafficRouter(fail_on_zero=True)
        partial = ProductionCanaryOrchestrator(
            self.catalog, self.controller(), partial_provider, partial_router,
            SignedTelemetryVerifier(self.catalog, {"telemetry_ed_key_001": self.telemetry_private.public_key()}),
        )
        partial_deployment = partial.stage(
            proposal_id="chg_structure_001", candidate_state=candidate, scope=scope,
            guardrails=self.guardrails(), approval_evidence=self.approval(candidate, scope),
            artifact_ref="registry.example/candidate@sha256:" + "a" * 64,
            artifact_hash="sha256:" + "a" * 64, isolation_execution_hash="sha256:" + "b" * 64,
        )
        with self.assertRaises(ANOError) as incomplete:
            partial.ingest(self.telemetry(
                partial_deployment["deployment_id"], {"success_rate": 0.5, "safety_incidents": 1, "cost": 1},
            ))
        self.assertEqual("CONTROL_PLANE_COMPENSATION_FAILED", incomplete.exception.code)
        self.assertEqual(1, partial_provider.rollbacks)

    @conformance("S-K8S-001")
    def test_kubernetes_adapter_is_digest_pinned_least_privilege_and_dry_run_by_default(self) -> None:
        digest = "sha256:" + "a" * 64
        provider = KubectlDeploymentProvider(context="prod-us-west", namespace="ano-canary")
        request = {
            "deployment_id": "can_k8s_001", "artifact_ref": "registry.example/ano/candidate@" + digest,
            "artifact_hash": digest, "isolation_execution_hash": "sha256:" + "b" * 64,
        }
        manifest = provider.build_manifest(request)
        deployment, network_policy = manifest["items"]
        pod_spec = deployment["spec"]["template"]["spec"]
        container = pod_spec["containers"][0]
        self.assertFalse(pod_spec["automountServiceAccountToken"])
        self.assertTrue(pod_spec["securityContext"]["runAsNonRoot"])
        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(["ALL"], container["securityContext"]["capabilities"]["drop"])
        self.assertEqual([], network_policy["spec"]["egress"])
        receipt = provider.stage(request)
        self.catalog.validate("deployment-receipt", receipt)
        self.assertEqual("staged", receipt["status"])


if __name__ == "__main__":
    unittest.main()
