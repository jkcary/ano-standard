from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any

from .errors import ANOError
from .util import parse_timestamp, sha256_json


class PermissionEngine:
    """Deterministic, fail-closed permission evaluator."""

    def __init__(self) -> None:
        self._grants: dict[str, dict[str, Any]] = {}
        self._uses: dict[str, int] = {}

    def register(self, grant: dict[str, Any]) -> None:
        grant_id = str(grant.get("grant_id", ""))
        if not grant_id:
            raise ANOError("SCHEMA_INVALID", "grant_id is required")
        if grant_id in self._grants:
            raise ANOError("STATE_CONFLICT", f"grant already exists: {grant_id}")
        self._grants[grant_id] = copy.deepcopy(grant)
        self._uses[grant_id] = 0

    def get(self, grant_id: str) -> dict[str, Any]:
        try:
            return copy.deepcopy(self._grants[grant_id])
        except KeyError as exc:
            raise ANOError("AUTH_MISSING", f"unknown grant: {grant_id}") from exc

    def revoke(self, grant_id: str, *, expected_version: int) -> dict[str, Any]:
        grant = self._grants.get(grant_id)
        if grant is None:
            raise ANOError("AUTH_MISSING", f"unknown grant: {grant_id}")
        if int(grant["version"]) != expected_version:
            raise ANOError("STATE_CONFLICT", "permission version changed")
        grant["status"] = "revoked"
        grant["version"] = int(grant["version"]) + 1
        return copy.deepcopy(grant)

    def authorize(
        self,
        action: dict[str, Any],
        *,
        now: datetime | None = None,
        consume: bool = False,
    ) -> dict[str, Any]:
        grant_id = str(action.get("permission_grant_id", ""))
        grant = self._grants.get(grant_id)
        if grant is None:
            raise ANOError("AUTH_MISSING", "action has no registered permission grant")
        if grant.get("status") != "active":
            code = "AUTH_REVOKED" if grant.get("status") == "revoked" else "AUTH_EXPIRED"
            raise ANOError(code, f"grant is not active: {grant.get('status')}")
        if action.get("actor_id") != grant.get("grantee_id"):
            raise ANOError("POLICY_DENIED", "grant belongs to a different grantee")
        if action.get("principal_id") != grant.get("principal_id"):
            raise ANOError("POLICY_DENIED", "principal does not match permission grant")
        if action.get("action_type") not in grant.get("capabilities", []):
            raise ANOError("POLICY_DENIED", "capability is outside grant scope")

        current = now or datetime.now(timezone.utc)
        if current < parse_timestamp(str(grant["valid_from"])):
            raise ANOError("AUTH_MISSING", "grant is not active yet")
        if current >= parse_timestamp(str(grant["expires_at"])):
            grant["status"] = "expired"
            raise ANOError("AUTH_EXPIRED", "grant has expired")

        parameters = action.get("parameters", {})
        actual_hash = sha256_json(parameters)
        if actual_hash != action.get("parameters_hash"):
            raise ANOError("PARAMETER_MISMATCH", "action parameters hash is invalid")
        required_hash = grant.get("constraints", {}).get("required_parameters_hash")
        if required_hash is not None and required_hash != actual_hash:
            raise ANOError("PARAMETER_MISMATCH", "parameters differ from approved content")

        self._check_resource_scope(parameters, grant.get("resource_scope", {}))
        max_actions = int(grant.get("constraints", {}).get("max_actions", 0))
        if max_actions <= 0 or self._uses[grant_id] >= max_actions:
            grant["status"] = "exhausted"
            raise ANOError("AUTH_EXPIRED", "grant action limit is exhausted")

        if consume:
            self._uses[grant_id] += 1
            if self._uses[grant_id] >= max_actions:
                grant["status"] = "exhausted"
        return copy.deepcopy(grant)

    @staticmethod
    def _check_resource_scope(parameters: dict[str, Any], scope: dict[str, Any]) -> None:
        for key, allowed in scope.items():
            if key not in parameters:
                raise ANOError("POLICY_DENIED", f"scoped parameter is missing: {key}")
            value = parameters[key]
            if isinstance(allowed, list):
                if value not in allowed:
                    raise ANOError("POLICY_DENIED", f"parameter is outside scope: {key}")
            elif value != allowed:
                raise ANOError("POLICY_DENIED", f"parameter is outside scope: {key}")

