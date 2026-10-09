from __future__ import annotations

import copy
from typing import Any

from .audit import TamperEvidentAuditLog
from .errors import ANOError
from .permissions import PermissionEngine
from .schema import SchemaCatalog
from .util import sha256_json


class ArtifactRegistry:
    def __init__(self, catalog: SchemaCatalog, *, trusted_signers: set[str]) -> None:
        self.catalog, self.trusted_signers = catalog, trusted_signers

    def deploy(self, artifact: dict[str, Any], payload: Any) -> dict[str, Any]:
        self.catalog.validate("artifact", artifact)
        signature = artifact["signature"]
        if artifact["status"] != "approved" or not signature["verified"] or signature["signer_id"] not in self.trusted_signers:
            raise ANOError("ARTIFACT_UNTRUSTED", "artifact is not approved by a trusted signer")
        if artifact["integrity_hash"] != sha256_json(payload):
            raise ANOError("ARTIFACT_INTEGRITY_FAILURE", "artifact digest mismatch")
        deployed = copy.deepcopy(artifact)
        deployed["status"] = "deployed"
        return deployed


class IncidentResponder:
    def __init__(self, catalog: SchemaCatalog, permissions: PermissionEngine, audit: TamperEvidentAuditLog) -> None:
        self.catalog, self.permissions, self.audit = catalog, permissions, audit
        self.scheduler_frozen = False
        self.isolated_assets: set[str] = set()

    def contain(self, incident: dict[str, Any], *, grant_versions: dict[str, int], assets: set[str]) -> dict[str, Any]:
        self.catalog.validate("incident", incident)
        self.scheduler_frozen = True
        for grant_id, version in grant_versions.items():
            self.permissions.revoke(grant_id, expected_version=version)
        self.isolated_assets.update(assets)
        updated = copy.deepcopy(incident)
        updated["status"], updated["version"] = "evidence_preserved", updated["version"] + 2
        updated["containment_actions"].extend(["scheduler_frozen", "credentials_revoked", "assets_isolated"])
        evidence = self.audit.append(actor_id="incident_controller", action_type="incident.contained", object_ids=[incident["incident_id"]], authorization_ref=None, result="evidence_preserved", policy_versions=[], metadata={"assets": sorted(assets)})
        updated["evidence_refs"].append(evidence["record_id"])
        self.catalog.validate("incident", updated)
        return updated


class LeaseManager:
    def __init__(self) -> None:
        self._epoch, self._holder, self.coordination_available = 0, None, True

    def acquire(self, holder_id: str) -> int:
        if not self.coordination_available:
            raise ANOError("SAFE_DEGRADED", "coordination unavailable; writes are frozen")
        self._epoch += 1
        self._holder = holder_id
        return self._epoch

    def authorize_write(self, holder_id: str, token: int) -> None:
        if not self.coordination_available:
            raise ANOError("SAFE_DEGRADED", "coordination unavailable; writes are frozen")
        if holder_id != self._holder or token != self._epoch:
            raise ANOError("STALE_FENCE", "stale leader cannot write")
