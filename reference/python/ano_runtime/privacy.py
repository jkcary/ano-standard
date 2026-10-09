from __future__ import annotations

import copy
from typing import Any

from .schema import SchemaCatalog
from .util import new_id, utc_now


class DataGovernanceService:
    def __init__(self, catalog: SchemaCatalog) -> None:
        self.catalog = catalog
        self._targets: dict[str, dict[str, Any]] = {}

    def register(self, *, subject_id: str, target_id: str, target_type: str, data: Any) -> None:
        self._targets[target_id] = {"subject_id": subject_id, "target_type": target_type, "data": copy.deepcopy(data), "status": "active"}

    def export(self, subject_id: str) -> dict[str, Any]:
        return {target_id: copy.deepcopy(value["data"]) for target_id, value in self._targets.items() if value["subject_id"] == subject_id and value["status"] == "active"}

    def delete(self, subject_id: str, *, fail_targets: set[str] | None = None) -> dict[str, Any]:
        fail_targets = fail_targets or set()
        targets, exceptions = [], []
        for target_id, entry in self._targets.items():
            if entry["subject_id"] != subject_id:
                continue
            if target_id in fail_targets:
                status = "unknown"
                exceptions.append({"target_id": target_id, "reason": "NO_ACKNOWLEDGEMENT"})
            else:
                status, entry["status"], entry["data"] = "deleted", "deleted", None
            targets.append({"target_id": target_id, "target_type": entry["target_type"], "status": status})
        request = {
            "request_id": new_id("del"), "schema_version": "0.3.0", "version": 2, "subject_id": subject_id,
            "scope": ["all_subject_data"], "targets": targets, "requested_at": utc_now(), "completed_at": utc_now(),
            "status": "partial" if exceptions else "completed", "exceptions": exceptions,
        }
        self.catalog.validate("deletion-request", request)
        return request
