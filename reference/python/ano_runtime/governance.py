from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .errors import ANOError
from .permissions import PermissionEngine
from .schema import SchemaCatalog
from .util import parse_timestamp, sha256_json, utc_now


@dataclass(frozen=True)
class PolicyDecision:
    outcome: str
    reason_codes: tuple[str, ...]
    policy_ids: tuple[str, ...]


class PolicyEngine:
    """Deterministic hierarchy; untrusted content is never interpreted as policy."""

    LEVEL = {"hard_safety": 0, "law": 1, "principal_denial": 2, "organization": 3, "permission_grant": 4, "preference": 5, "model_recommendation": 6}

    def __init__(self, catalog: SchemaCatalog) -> None:
        self.catalog = catalog
        self._policies: dict[str, dict[str, Any]] = {}

    def register(self, policy: dict[str, Any]) -> None:
        self.catalog.validate("policy", policy)
        self._policies[str(policy["policy_id"])] = copy.deepcopy(policy)

    @staticmethod
    def _matches(scope: dict[str, Any], context: dict[str, Any]) -> bool:
        for key, expected in scope.items():
            actual = context.get(key)
            if (isinstance(expected, list) and actual not in expected) or (not isinstance(expected, list) and actual != expected):
                return False
        return True

    def evaluate(self, context: dict[str, Any], *, now: datetime | None = None) -> PolicyDecision:
        current = now or datetime.now(timezone.utc)
        applicable = []
        for policy in self._policies.values():
            if policy["status"] != "active" or current < parse_timestamp(policy["valid_from"]):
                continue
            if policy["expires_at"] is not None and current >= parse_timestamp(policy["expires_at"]):
                continue
            if self._matches(policy["scope"], context):
                applicable.append(policy)
        if not applicable:
            return PolicyDecision("deny", ("NO_APPLICABLE_POLICY",), ())
        best_level = min(self.LEVEL[item["source_level"]] for item in applicable)
        highest = [item for item in applicable if self.LEVEL[item["source_level"]] == best_level]
        best_priority = max(int(item["priority"]) for item in highest)
        decisive = [item for item in highest if int(item["priority"]) == best_priority]
        effects = {str(item["effect"]) for item in decisive}
        policy_ids = tuple(sorted(str(item["policy_id"]) for item in decisive))
        reasons = tuple(sorted({code for item in decisive for code in item["reason_codes"]}))
        if "deny" in effects:
            return PolicyDecision("deny", reasons, policy_ids)
        if len(effects) != 1:
            return PolicyDecision("deny", ("POLICY_CONFLICT",), policy_ids)
        return PolicyDecision(next(iter(effects)), reasons, policy_ids)


class RiskMatrix:
    def __init__(self, catalog: SchemaCatalog, matrix_version: str = "risk_matrix_v1") -> None:
        self.catalog = catalog
        self.matrix_version = matrix_version

    def assess(self, subject_id: str, dimensions: dict[str, int]) -> dict[str, Any]:
        required = {"external_effect", "irreversibility", "financial", "privacy", "legal", "affected_people", "uncertainty"}
        if set(dimensions) != required or any(not 0 <= value <= 3 for value in dimensions.values()):
            raise ANOError("RISK_INPUT_INVALID", "risk dimensions must be complete values from 0 to 3")
        peak, total = max(dimensions.values()), sum(dimensions.values())
        if peak == 3 or total >= 14:
            level, assurance = "critical", "strong_multi_party"
        elif peak == 2 or total >= 8:
            level, assurance = "high", "strong_multi_party"
        elif total >= 3:
            level, assurance = "medium", "explicit_confirmation"
        else:
            level, assurance = "low", "implicit_low_risk"
        result = {"assessment_id": f"risk_{sha256_json([subject_id, dimensions])[7:31]}", "schema_version": "0.3.0", "subject_id": subject_id, "matrix_version": self.matrix_version, "dimensions": copy.deepcopy(dimensions), "risk_level": level, "required_assurance": assurance, "reason_codes": [f"RISK_{level.upper()}"], "assessed_at": utc_now()}
        self.catalog.validate("risk-assessment", result)
        return result


class ApprovalService:
    def __init__(self, catalog: SchemaCatalog) -> None:
        self.catalog = catalog
        self._approvals: dict[str, dict[str, Any]] = {}
        self._domains: dict[str, dict[str, str]] = {}

    def submit(self, approval: dict[str, Any], *, proposer_domain: str) -> None:
        self.catalog.validate("approval", approval)
        if approval["status"] != "requested" or approval["decisions"]:
            raise ANOError("APPROVAL_STATE_INVALID", "new approval must be undecided and requested")
        approval_id = str(approval["approval_id"])
        self._approvals[approval_id] = copy.deepcopy(approval)
        self._domains[approval_id] = {str(approval["proposer_id"]): proposer_domain}

    def decide(self, approval_id: str, *, approver_id: str, role: str, decision: str, independence_domain: str) -> dict[str, Any]:
        approval = self._approvals[approval_id]
        if approval["status"] != "requested":
            raise ANOError("APPROVAL_CLOSED", "approval is no longer open")
        if datetime.now(timezone.utc) >= parse_timestamp(approval["expires_at"]):
            approval["status"] = "expired"
            approval["version"] += 1
            raise ANOError("APPROVAL_EXPIRED", "approval expired before all roles decided")
        if decision not in {"approve", "reject"}:
            raise ANOError("APPROVAL_DECISION_INVALID", f"unsupported decision: {decision}")
        if approver_id == approval["proposer_id"] or independence_domain in self._domains[approval_id].values():
            raise ANOError("SEPARATION_VIOLATION", "approver is not independent of proposer or prior approver")
        if role not in approval["required_roles"]:
            raise ANOError("APPROVER_ROLE_INVALID", f"role is not required: {role}")
        if any(item["role"] == role for item in approval["decisions"]):
            raise ANOError("APPROVER_ROLE_DUPLICATE", f"role already decided: {role}")
        approval["decisions"].append({"approver_id": approver_id, "role": role, "decision": decision, "decided_at": utc_now()})
        self._domains[approval_id][approver_id] = independence_domain
        if decision == "reject":
            approval["status"] = "rejected"
        elif {item["role"] for item in approval["decisions"] if item["decision"] == "approve"} == set(approval["required_roles"]):
            approval["status"] = "approved"
        approval["version"] += 1
        self.catalog.validate("approval", approval)
        return copy.deepcopy(approval)

    def authorize(self, approval_id: str, parameters: dict[str, Any], *, now: datetime | None = None) -> None:
        approval = self._approvals[approval_id]
        if approval["status"] != "approved":
            raise ANOError("APPROVAL_MISSING", "approval is not complete")
        if (now or datetime.now(timezone.utc)) >= parse_timestamp(approval["expires_at"]):
            raise ANOError("APPROVAL_EXPIRED", "approval expired")
        if sha256_json(parameters) != approval["parameters_hash"]:
            raise ANOError("PARAMETER_MISMATCH", "approved parameters changed")


class RevocationCoordinator:
    def __init__(self, permissions: PermissionEngine) -> None:
        self.permissions = permissions
        self.actions: dict[str, dict[str, str]] = {}

    def track(self, action_id: str, grant_id: str, status: str) -> None:
        self.actions[action_id] = {"grant_id": grant_id, "status": status}

    def revoke(self, grant_id: str, *, expected_version: int) -> dict[str, Any]:
        grant = self.permissions.revoke(grant_id, expected_version=expected_version)
        for action in self.actions.values():
            if action["grant_id"] == grant_id:
                if action["status"] in {"proposed", "validated", "authorized"}:
                    action["status"] = "cancelled"
                elif action["status"] in {"executing", "unknown"}:
                    action["status"] = "escalated"
        return grant


class DelegationGraph:
    def __init__(self, catalog: SchemaCatalog) -> None:
        self.catalog = catalog
        self._nodes: dict[str, dict[str, Any]] = {}

    def delegate(self, delegation: dict[str, Any], *, parent: dict[str, Any]) -> None:
        self.catalog.validate("delegation", delegation)
        if not set(delegation["capabilities"]) <= set(parent["capabilities"]):
            raise ANOError("DELEGATION_SCOPE_EXPANSION", "delegated capabilities exceed parent")
        if not set(delegation["data_scope"]) <= set(parent.get("data_scope", delegation["data_scope"])):
            raise ANOError("DELEGATION_SCOPE_EXPANSION", "delegated data exceeds parent")
        for key, allowed in delegation["resource_scope"].items():
            parent_allowed = parent.get("resource_scope", {}).get(key)
            values = set(allowed if isinstance(allowed, list) else [allowed])
            parents = set(parent_allowed if isinstance(parent_allowed, list) else [parent_allowed])
            if parent_allowed is None or not values <= parents:
                raise ANOError("DELEGATION_SCOPE_EXPANSION", f"resource exceeds parent: {key}")
        self._nodes[str(delegation["delegation_id"])] = copy.deepcopy(delegation)

    def revoke_tree(self, delegation_id: str, *, unreachable: set[str] | None = None) -> dict[str, str]:
        unreachable = unreachable or set()
        statuses: dict[str, str] = {}

        def visit(node_id: str) -> None:
            node = self._nodes[node_id]
            node["status"] = "unknown" if node_id in unreachable else "revoked"
            node["version"] += 1
            statuses[node_id] = node["status"]
            for child_id in node["downstream_ids"]:
                visit(child_id)

        visit(delegation_id)
        return statuses


class BudgetLedger:
    def __init__(self, limit: float) -> None:
        self.limit, self.spent = limit, 0.0

    def charge(self, amount: float, *, task_id: str, parent_task_id: str | None = None) -> None:
        if amount < 0:
            raise ANOError("COST_INVALID", "cost cannot be negative")
        if self.spent + amount > self.limit:
            raise ANOError("BUDGET_EXCEEDED", f"aggregate budget exceeded by {task_id}")
        self.spent += amount


class IdentityGovernance:
    @staticmethod
    def fork(identity: dict[str, Any], *, new_organism_id: str) -> dict[str, Any]:
        clone = copy.deepcopy(identity)
        clone.update({"organism_id": new_organism_id, "parent_organism_id": identity.get("organism_id"), "credentials": [], "permission_grants": [], "commitments": []})
        return clone


class RecoveryCouncil:
    def __init__(self, *, threshold: int, required_roles: set[str]) -> None:
        if threshold < 2:
            raise ValueError("identity-root recovery threshold must require multiple actors")
        self.threshold, self.required_roles, self._approvals = threshold, required_roles, {}

    def approve(self, actor_id: str, role: str) -> None:
        self._approvals[actor_id] = role

    def recover(self) -> bool:
        return len(self._approvals) >= self.threshold and self.required_roles <= set(self._approvals.values())


class AppealService:
    def __init__(self) -> None:
        self._cases: dict[str, dict[str, Any]] = {}

    def open(self, case_id: str, decision: dict[str, Any]) -> None:
        self._cases[case_id] = {"original": copy.deepcopy(decision), "status": "open", "reassessment": None}

    def correct_and_reassess(self, case_id: str, corrected_data: dict[str, Any], evaluator: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
        reassessed = evaluator(copy.deepcopy(corrected_data))
        self._cases[case_id].update({"status": "reassessed", "corrected_data": copy.deepcopy(corrected_data), "reassessment": reassessed})
        return copy.deepcopy(self._cases[case_id])
