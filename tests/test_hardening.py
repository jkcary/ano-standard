from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ano_runtime import (
    ANOError, ApprovalEvidenceVerifier, AttestedSandboxRunner, CanaryController,
    CanaryJournal, DockerSandboxBackend, IsolationAttestationVerifier, SchemaCatalog, sha256_json,
    sign_hmac_record, utc_now,
)

from tests.support import STANDARD_ROOT, conformance


class RecordingBackend:
    backend_id = "container_backend_001"

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: dict) -> dict:
        self.calls += 1
        return {
            "output": {"result": request["inputs"]["fixture"]}, "status": "passed",
            "denied_attempts": [], "resource_usage": {"cpu_ms": 2, "memory_mb": 8},
        }


class ProductionHardeningConformanceTests(unittest.TestCase):
    APPROVAL_KEY = b"test-only-independent-approval-service-key"
    ISOLATION_KEY = b"test-only-independent-isolation-verifier-key"

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")
        cls.machine = STANDARD_ROOT / "state-machines" / "v0.3.0" / "canary-deployment.machine.json"

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

    def legacy_approval(self, candidate: dict, scope: dict) -> dict:
        return {
            "approved": True, "proposal_id": "chg_structure_001",
            "candidate_hash": sha256_json(candidate), "scope_hash": sha256_json(scope),
            "issued_at": utc_now(), "expires_at": "2099-01-01T00:00:00Z", "proposer_domain": "architecture_domain",
            "independent_domains": ["safety_board", "principal_board"],
            "approved_permissions": ["read_metrics"],
        }

    def signed_approval(self, candidate: dict, scope: dict) -> dict:
        return sign_hmac_record({
            "evidence_id": "sev_test_001", "schema_version": "0.3.0", "proposal_id": "chg_structure_001",
            "candidate_hash": sha256_json(candidate), "scope_hash": sha256_json(scope),
            "issued_at": utc_now(), "expires_at": "2099-01-01T00:00:00Z", "proposer_domain": "architecture_domain",
            "approvals": [
                {"approver_id": "human_safety_001", "independence_domain": "safety_board"},
                {"approver_id": "human_owner_001", "independence_domain": "principal_board"},
            ],
            "approved_permissions": ["read_metrics"], "issuer": "approval_service_001",
            "key_id": "approval_key_001",
        }, self.APPROVAL_KEY)

    def attestation(self, artifact: dict, *, network: str = "none") -> dict:
        return sign_hmac_record({
            "attestation_id": "isa_test_001", "schema_version": "0.3.0",
            "artifact_hash": sha256_json(artifact), "backend_id": "container_backend_001",
            "controls": {
                "process_isolation": "container", "network": network,
                "filesystem": "ephemeral_read_only_root", "credentials": "none",
                "resource_limits": True, "audit": "complete",
            },
            "issued_at": utc_now(), "expires_at": "2099-01-01T00:00:00Z",
            "issuer": "isolation_verifier_001", "key_id": "isolation_key_001",
        }, self.ISOLATION_KEY)

    @conformance("S-HSBX-001")
    def test_attested_sandbox_fails_closed_before_unverified_backend_execution(self) -> None:
        artifact = {"image": "candidate@sha256"}
        backend = RecordingBackend()
        verifier = IsolationAttestationVerifier(self.catalog, {"isolation_key_001": self.ISOLATION_KEY})
        runner = AttestedSandboxRunner(self.catalog, verifier)
        limits = {"cpu_ms": 1000, "memory_mb": 128, "wall_time_ms": 2000, "network": "none", "filesystem": "isolated_output"}
        with self.assertRaises(ANOError) as rejected:
            runner.run(
                backend=backend, attestation=self.attestation(artifact, network="allowlist"),
                proposal_id="chg_structure_001", artifact=artifact, inputs={"fixture": "safe"},
                allowed_inputs={"fixture"}, allowed_outputs={"result"}, limits=limits,
            )
        self.assertEqual("ISOLATION_CONTROL_MISSING", rejected.exception.code)
        self.assertEqual(0, backend.calls)

        valid_attestation = self.attestation(artifact)
        output, record = runner.run(
            backend=backend, attestation=valid_attestation, proposal_id="chg_structure_001",
            artifact=artifact, inputs={"fixture": "safe", "secret": "not_mounted"},
            allowed_inputs={"fixture"}, allowed_outputs={"result"}, limits=limits,
        )
        self.assertEqual({"result": "safe"}, output)
        self.assertEqual("isa_test_001", record["isolation_attestation_id"])
        self.assertEqual(sha256_json(valid_attestation), record["isolation_attestation_hash"])
        self.assertEqual(1, backend.calls)

        docker = DockerSandboxBackend(
            "registry.example/ano-sandbox@sha256:" + "a" * 64, ["python", "/runner/main.py"],
        )
        docker_command = docker.command_for(limits)
        for required in ["--network", "none", "--read-only", "--cap-drop", "ALL", "no-new-privileges", "--pids-limit", "--memory", "--ulimit"]:
            self.assertIn(required, docker_command)
        self.assertFalse(any(item.startswith("--volume") or item == "-v" for item in docker_command))

    @conformance("S-SIG-001")
    def test_production_canary_rejects_tampered_approval_evidence(self) -> None:
        candidate, scope = {"planner": "candidate-v3"}, self.scope()
        verifier = ApprovalEvidenceVerifier(self.catalog, {"approval_key_001": self.APPROVAL_KEY})
        controller = CanaryController(
            self.catalog, self.machine, {"planner": "stable-v1"},
            approval_verifier=verifier, require_verified_approval=True,
        )
        tampered = self.signed_approval(candidate, scope)
        tampered["approved_permissions"].append("funds.transfer")
        with self.assertRaises(ANOError) as rejected:
            controller.create(
                proposal_id="chg_structure_001", candidate_state=candidate, scope=scope,
                guardrails=self.guardrails(), approval_evidence=tampered,
            )
        self.assertEqual("APPROVAL_SIGNATURE_INVALID", rejected.exception.code)
        self.assertEqual({"planner": "stable-v1"}, controller.current_state)

        duplicate_actor = self.signed_approval(candidate, scope)
        duplicate_actor["approvals"][1]["approver_id"] = duplicate_actor["approvals"][0]["approver_id"]
        duplicate_actor = sign_hmac_record(duplicate_actor, self.APPROVAL_KEY)
        with self.assertRaises(ANOError) as separation:
            controller.create(
                proposal_id="chg_structure_001", candidate_state=candidate, scope=scope,
                guardrails=self.guardrails(), approval_evidence=duplicate_actor,
            )
        self.assertEqual("SEPARATION_VIOLATION", separation.exception.code)

        valid_approval = self.signed_approval(candidate, scope)
        deployment = controller.create(
            proposal_id="chg_structure_001", candidate_state=candidate, scope=scope,
            guardrails=self.guardrails(), approval_evidence=valid_approval,
        )
        self.assertEqual("running", deployment["status"])
        self.assertEqual("sev_test_001", deployment["approval_evidence_id"])
        self.assertEqual(sha256_json(valid_approval), deployment["approval_evidence_hash"])

    @conformance("S-TEL-001")
    def test_unsafe_telemetry_is_durable_before_verified_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = CanaryJournal(Path(directory) / "canary.jsonl", self.catalog)
            candidate, scope = {"planner": "candidate-v3"}, self.scope()
            controller = CanaryController(
                self.catalog, self.machine, {"planner": "stable-v1"}, journal=journal,
            )
            controller.create(
                proposal_id="chg_structure_001", candidate_state=candidate, scope=scope,
                guardrails=self.guardrails(), approval_evidence=self.legacy_approval(candidate, scope),
            )
            self.assertEqual("rolled_back", controller.observe({"success_rate": 0.5, "safety_incidents": 1, "cost": 1}))
            events = [record["event_type"] for record in journal.records()]
            self.assertEqual(["canary.started", "canary.telemetry_observed", "canary.rolled_back"], events)
            reloaded = CanaryJournal(Path(directory) / "canary.jsonl", self.catalog)
            self.assertEqual(3, len(reloaded.records()))
            self.assertEqual(reloaded.records()[1]["record_hash"], reloaded.records()[2]["previous_hash"])
            path = Path(directory) / "canary.jsonl"
            path.write_text(path.read_text(encoding="utf-8").replace("candidate-v3", "candidate-v4"), encoding="utf-8")
            with self.assertRaises(ANOError) as corrupted:
                CanaryJournal(path, self.catalog)
            self.assertEqual("CANARY_JOURNAL_CORRUPT", corrupted.exception.code)

    @conformance("S-REC-001")
    def test_restart_recovers_unsafe_running_canary_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "canary.jsonl"
            journal = CanaryJournal(path, self.catalog)
            candidate, scope = {"planner": "candidate-v3"}, self.scope()

            def crash_after_durable_telemetry() -> None:
                raise RuntimeError("simulated process crash")

            controller = CanaryController(
                self.catalog, self.machine, {"planner": "stable-v1"}, journal=journal,
                post_telemetry_hook=crash_after_durable_telemetry,
            )
            controller.create(
                proposal_id="chg_structure_001", candidate_state=candidate, scope=scope,
                guardrails=self.guardrails(), approval_evidence=self.legacy_approval(candidate, scope),
            )
            with self.assertRaisesRegex(RuntimeError, "simulated process crash"):
                controller.observe({"success_rate": 0.5, "safety_incidents": 1, "cost": 1})

            recovered = CanaryController.recover(self.catalog, self.machine, CanaryJournal(path, self.catalog))
            self.assertEqual({"planner": "stable-v1"}, recovered.current_state)
            self.assertIsNotNone(recovered.rollback_record)
            self.assertEqual("canary.rolled_back", CanaryJournal(path, self.catalog).records()[-1]["event_type"])


if __name__ == "__main__":
    unittest.main()
