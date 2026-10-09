from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable

from .errors import ANOError
from .schema import SchemaCatalog
from .state_machine import StateMachine
from .util import new_id, parse_timestamp, sha256_json, utc_now


class StructuralApprovalGate:
    """L5 changes require multiple independent approval domains."""

    def __init__(self, *, minimum_approvals: int = 2) -> None:
        if minimum_approvals < 2:
            raise ValueError("L5 structural changes require at least two approvals")
        self.minimum_approvals = minimum_approvals
        self._proposals: dict[str, dict[str, Any]] = {}

    def submit(self, proposal: dict[str, Any], *, proposer_domain: str) -> None:
        if proposal.get("change_level") != "L5_STRUCTURE" or proposal.get("status") != "proposed":
            raise ANOError("STRUCTURAL_PROPOSAL_INVALID", "gate accepts only proposed L5 changes")
        self._proposals[str(proposal["proposal_id"])] = {
            "proposal": copy.deepcopy(proposal), "proposer_domain": proposer_domain, "approvals": {},
        }

    def approve(self, proposal_id: str, *, approver_id: str, independence_domain: str) -> bool:
        record = self._proposals[proposal_id]
        proposal = record["proposal"]
        if approver_id == proposal["proposer_id"] or independence_domain == record["proposer_domain"]:
            raise ANOError("SEPARATION_VIOLATION", "proposer or proposer domain cannot approve structural change")
        if independence_domain in record["approvals"].values():
            raise ANOError("SEPARATION_VIOLATION", "approvals must come from independent domains")
        record["approvals"][approver_id] = independence_domain
        return len(record["approvals"]) >= self.minimum_approvals


class ProtectedEvaluationAssets:
    """Rejects structural patches that touch baselines, judges, answers, or thresholds."""

    PROTECTED = {"baseline", "baselines", "evaluator", "judge", "holdout", "answers", "threshold", "thresholds", "audit"}

    def __init__(self, *, baseline: Any, evaluator: Any, thresholds: Any) -> None:
        self._seals = {
            "baseline": sha256_json(baseline), "evaluator": sha256_json(evaluator), "thresholds": sha256_json(thresholds),
        }

    @property
    def seals(self) -> dict[str, str]:
        return copy.deepcopy(self._seals)

    def authorize_patch(self, patch: dict[str, Any]) -> None:
        def walk(value: Any, path: tuple[str, ...] = ()) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    normalized = key.lower().replace("-", "_")
                    if any(token in normalized for token in self.PROTECTED):
                        raise ANOError("EVALUATION_ASSET_PROTECTED", f"patch targets protected asset at {'.'.join((*path, key))}")
                    walk(child, (*path, key))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, (*path, str(index)))

        before = self.seals
        walk(patch)
        if self.seals != before:
            raise ANOError("EVALUATION_INTEGRITY_FAILURE", "evaluation seals changed during authorization")


class SandboxView:
    def __init__(self, inputs: dict[str, Any], allowed_inputs: set[str], denied_attempts: list[dict[str, str]]) -> None:
        self._inputs = {key: copy.deepcopy(value) for key, value in inputs.items() if key in allowed_inputs}
        self._denied = denied_attempts

    def read_input(self, key: str) -> Any:
        if key not in self._inputs:
            self._deny("undeclared_input", f"input is not declared: {key}")
        return copy.deepcopy(self._inputs[key])

    def read_production(self, _reference: str) -> Any:
        self._deny("production_data", "sandbox has no production data mount")

    def get_credential(self, _name: str) -> str:
        self._deny("credential", "sandbox has no production credential provider")

    def network(self, _destination: str) -> None:
        self._deny("network", "sandbox network is disabled")

    def _deny(self, capability: str, reason: str) -> None:
        self._denied.append({"capability": capability, "reason": reason})
        raise ANOError("SANDBOX_DENIED", reason)


class StructuralSandbox:
    """Capability-envelope reference sandbox; production deployments require OS/process isolation."""

    def __init__(self, catalog: SchemaCatalog) -> None:
        self.catalog = catalog

    def run(
        self,
        *,
        proposal_id: str,
        artifact: Any,
        candidate: Callable[[SandboxView], Any],
        inputs: dict[str, Any],
        allowed_inputs: set[str],
        allowed_outputs: set[str],
    ) -> tuple[Any, dict[str, Any]]:
        denied: list[dict[str, str]] = []
        view = SandboxView(inputs, allowed_inputs, denied)
        started = utc_now()
        output: Any = None
        try:
            output = candidate(view)
            status = "blocked" if denied else "passed"
        except ANOError as exc:
            if exc.code != "SANDBOX_DENIED":
                raise
            status = "blocked"
        if denied:
            output = None
        if isinstance(output, dict) and not set(output) <= allowed_outputs:
            denied.append({"capability": "undeclared_output", "reason": "candidate emitted undeclared output"})
            output, status = None, "blocked"
        record = {
            "execution_id": new_id("sbx"), "schema_version": "0.3.0", "proposal_id": proposal_id,
            "artifact_hash": sha256_json(artifact),
            "limits": {"cpu_ms": 1000, "memory_mb": 128, "wall_time_ms": 2000, "network": "none", "filesystem": "isolated_output"},
            "allowed_inputs": sorted(allowed_inputs), "allowed_outputs": sorted(allowed_outputs), "denied_attempts": denied,
            "resource_usage": {"cpu_ms": 0, "memory_mb": 0}, "started_at": started, "finished_at": utc_now(), "status": status,
        }
        self.catalog.validate("sandbox-execution", record)
        return copy.deepcopy(output), record


class CanaryController:
    """Five-dimensional scope enforcement with guardrail-triggered verified rollback."""

    def __init__(
        self,
        catalog: SchemaCatalog,
        machine_path: str | Path,
        production_state: dict[str, Any],
        *,
        journal: Any | None = None,
        approval_verifier: Any | None = None,
        require_verified_approval: bool = False,
        post_telemetry_hook: Callable[[], None] | None = None,
    ) -> None:
        self.catalog = catalog
        self.machine = StateMachine.from_file(machine_path)
        self._baseline = copy.deepcopy(production_state)
        self._current = copy.deepcopy(production_state)
        self._deployment: dict[str, Any] | None = None
        self._spent = 0.0
        self.rollback_record: dict[str, Any] | None = None
        self._journal = journal
        self._approval_verifier = approval_verifier
        self._require_verified_approval = require_verified_approval
        self._post_telemetry_hook = post_telemetry_hook
        if require_verified_approval and approval_verifier is None:
            raise ValueError("production canary requires an approval evidence verifier")

    @property
    def current_state(self) -> dict[str, Any]:
        return copy.deepcopy(self._current)

    def snapshot(self) -> dict[str, Any]:
        if self._deployment is None:
            raise ANOError("CANARY_NOT_CREATED", "canary has no durable state to snapshot")
        return {
            "baseline": copy.deepcopy(self._baseline), "current": copy.deepcopy(self._current),
            "deployment": copy.deepcopy(self._deployment), "spent": self._spent,
            "rollback_record": copy.deepcopy(self.rollback_record),
        }

    @classmethod
    def recover(
        cls,
        catalog: SchemaCatalog,
        machine_path: str | Path,
        journal: Any,
        *,
        approval_verifier: Any | None = None,
        require_verified_approval: bool = False,
    ) -> "CanaryController":
        latest = journal.latest()
        if latest is None:
            raise ANOError("CANARY_RECOVERY_EMPTY", "no durable canary checkpoint exists")
        snapshot = latest["snapshot"]
        controller = cls(
            catalog, machine_path, snapshot["baseline"], journal=journal,
            approval_verifier=approval_verifier, require_verified_approval=require_verified_approval,
        )
        controller._current = copy.deepcopy(snapshot["current"])
        controller._deployment = copy.deepcopy(snapshot["deployment"])
        controller._spent = float(snapshot["spent"])
        controller.rollback_record = copy.deepcopy(snapshot["rollback_record"])
        deployment = controller._deployment
        assert deployment is not None
        catalog.validate("canary-deployment", deployment)
        if sha256_json(controller._baseline) != deployment["baseline_hash"]:
            raise ANOError("CANARY_RECOVERY_INTEGRITY", "durable baseline does not match deployment")
        if deployment["status"] in {"running", "promoted"} and sha256_json(controller._current) != deployment["candidate_hash"]:
            raise ANOError("CANARY_RECOVERY_INTEGRITY", "durable candidate state does not match deployment")
        if deployment["status"] == "rolled_back" and sha256_json(controller._current) != deployment["baseline_hash"]:
            raise ANOError("CANARY_RECOVERY_INTEGRITY", "rolled back state does not match baseline")
        if deployment["status"] == "running":
            triggers = controller._guardrail_triggers(deployment["metrics"])
            if triggers:
                controller._rollback(triggers)
        return controller

    def create(
        self,
        *,
        proposal_id: str,
        candidate_state: dict[str, Any],
        scope: dict[str, Any],
        guardrails: dict[str, Any],
        approval_evidence: dict[str, Any],
    ) -> dict[str, Any]:
        if self._approval_verifier is not None:
            self._approval_verifier.verify(approval_evidence)
        elif self._require_verified_approval:
            raise ANOError("APPROVAL_VERIFIER_REQUIRED", "production canary requires verified approval evidence")
        approval_rows = approval_evidence.get("approvals", [])
        domains = {
            str(item.get("independence_domain")) for item in approval_rows if isinstance(item, dict)
        } or set(approval_evidence.get("independent_domains", []))
        proposer_domain = approval_evidence.get("proposer_domain")
        approved = bool(approval_rows) or bool(approval_evidence.get("approved"))
        if not approved or len(domains) < 2 or proposer_domain in domains:
            raise ANOError("SEPARATION_VIOLATION", "canary requires two independent approvals outside proposer domain")
        approved_permissions = set(approval_evidence.get("approved_permissions", []))
        requested_permissions = set(scope.get("permissions", []))
        if not requested_permissions <= approved_permissions:
            raise ANOError(
                "CANARY_PERMISSION_ESCALATION",
                "canary scope contains permissions not explicitly present in approval evidence",
            )
        candidate_hash = sha256_json(candidate_state)
        if (
            approval_evidence.get("proposal_id") != proposal_id
            or approval_evidence.get("candidate_hash") != candidate_hash
            or approval_evidence.get("scope_hash") != sha256_json(scope)
        ):
            raise ANOError("APPROVAL_BINDING_MISMATCH", "approval does not bind this proposal, candidate, and canary scope")
        try:
            expired = parse_timestamp(str(approval_evidence["expires_at"])) <= parse_timestamp(utc_now())
        except (KeyError, TypeError, ValueError) as exc:
            raise ANOError("APPROVAL_EVIDENCE_INVALID", "approval expiry must be a timezone-aware timestamp") from exc
        if expired:
            raise ANOError("APPROVAL_EXPIRED", "structural approval has expired")
        deployment = {
            "deployment_id": new_id("can"), "schema_version": "0.3.0", "version": 1, "proposal_id": proposal_id,
            "baseline_hash": sha256_json(self._baseline), "candidate_hash": candidate_hash,
            "scope": copy.deepcopy(scope), "guardrails": copy.deepcopy(guardrails), "metrics": {},
            "rollback_plan_id": "rollback_structural_standard", "started_at": utc_now(), "finished_at": None, "status": "proposed",
        }
        if "evidence_id" in approval_evidence:
            deployment["approval_evidence_id"] = approval_evidence["evidence_id"]
            deployment["approval_evidence_hash"] = sha256_json(approval_evidence)
        self.catalog.validate("canary-deployment", deployment)
        deployment["status"] = self.machine.transition("proposed", "canary.approved", {"independent_approval", "scope_complete", "rollback_rehearsed"})
        deployment["status"] = self.machine.transition("approved", "canary.started", {"baseline_sealed", "candidate_verified", "telemetry_active"})
        deployment["version"] += 2
        self._current = copy.deepcopy(candidate_state)
        self._deployment = deployment
        self.catalog.validate("canary-deployment", deployment)
        self._checkpoint("canary.started")
        return copy.deepcopy(deployment)

    def authorize(self, *, identity_id: str, traffic_fraction: float, permissions: set[str], data_refs: set[str], cost: float, currency: str = "USD") -> None:
        if self._deployment is None or self._deployment["status"] != "running":
            raise ANOError("CANARY_NOT_RUNNING", "no running canary")
        scope = self._deployment["scope"]
        if traffic_fraction < 0 or cost < 0:
            raise ANOError("CANARY_SCOPE_INVALID", "traffic and cost cannot be negative")
        if identity_id not in scope["identity_ids"]:
            raise ANOError("CANARY_IDENTITY_SCOPE", "identity outside canary")
        if traffic_fraction > scope["traffic_fraction"]:
            raise ANOError("CANARY_TRAFFIC_SCOPE", "traffic exceeds canary fraction")
        if not permissions <= set(scope["permissions"]):
            raise ANOError("CANARY_PERMISSION_SCOPE", "permission outside canary")
        if not data_refs <= set(scope["data_refs"]):
            raise ANOError("CANARY_DATA_SCOPE", "data outside canary")
        if currency != scope["budget"]["currency"] or self._spent + cost > float(scope["budget"]["amount"]):
            raise ANOError("CANARY_BUDGET_SCOPE", "budget outside canary")
        self._spent += cost
        self._checkpoint("canary.budget_updated")

    def observe(self, metrics: dict[str, float], *, observation_window_complete: bool = False) -> str:
        if self._deployment is None or self._deployment["status"] != "running":
            raise ANOError("CANARY_NOT_RUNNING", "no running canary")
        self._deployment["metrics"] = copy.deepcopy(metrics)
        self._checkpoint("canary.telemetry_observed")
        if self._post_telemetry_hook is not None:
            self._post_telemetry_hook()
        triggers = self._guardrail_triggers(metrics)
        if triggers:
            return self._rollback(triggers)
        if observation_window_complete:
            self._deployment["status"] = self.machine.transition("running", "canary.promoted", {"guardrails_passed", "observation_window_complete"})
            self._deployment["finished_at"] = utc_now()
            self._deployment["version"] += 1
        self.catalog.validate("canary-deployment", self._deployment)
        if observation_window_complete:
            self._checkpoint("canary.promoted")
        return str(self._deployment["status"])

    def _guardrail_triggers(self, metrics: dict[str, float]) -> list[str]:
        assert self._deployment is not None
        guardrails = self._deployment["guardrails"]
        triggers = []
        if metrics.get("success_rate", 0) < guardrails["minimum_success_rate"]:
            triggers.append("PERFORMANCE_REGRESSION")
        if metrics.get("safety_incidents", 0) > guardrails["maximum_safety_incidents"]:
            triggers.append("SAFETY_REGRESSION")
        if metrics.get("cost", 0) > guardrails["maximum_cost"]:
            triggers.append("COST_REGRESSION")
        return triggers

    def fail_safe_rollback(self, trigger_code: str) -> str:
        if self._deployment is None or self._deployment["status"] != "running":
            raise ANOError("CANARY_NOT_RUNNING", "no running canary to roll back")
        return self._rollback([trigger_code])

    def _checkpoint(self, event_type: str) -> None:
        if self._journal is not None:
            self._journal.append(event_type, self.snapshot())

    def _rollback(self, triggers: list[str]) -> str:
        assert self._deployment is not None
        self._current = copy.deepcopy(self._baseline)
        restored_hash = sha256_json(self._current)
        verified = restored_hash == self._deployment["baseline_hash"]
        if not verified:
            raise ANOError("ROLLBACK_INTEGRITY_FAILURE", "restored state does not match baseline")
        self._deployment["status"] = self.machine.transition("running", "canary.rolled_back", {"baseline_restored", "restoration_verified"})
        self._deployment["finished_at"] = utc_now()
        self._deployment["version"] += 1
        self.rollback_record = {
            "rollback_id": new_id("rbk"), "schema_version": "0.3.0", "deployment_id": self._deployment["deployment_id"],
            "trigger_codes": triggers, "candidate_hash": self._deployment["candidate_hash"], "baseline_hash": self._deployment["baseline_hash"],
            "restored_hash": restored_hash, "restored_at": utc_now(), "verification_method": "canonical_state_hash", "verified": True, "residual_effects": [],
        }
        self.catalog.validate("rollback-record", self.rollback_record)
        self.catalog.validate("canary-deployment", self._deployment)
        self._checkpoint("canary.rolled_back")
        return "rolled_back"
