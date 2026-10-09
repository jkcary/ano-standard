from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .errors import ANOError
from .schema import SchemaCatalog
from .util import new_id, sha256_json, utc_now


class TamperEvidentAuditLog:
    def __init__(self, catalog: SchemaCatalog, path: str | Path | None = None) -> None:
        self.catalog = catalog
        self.path = Path(path) if path else None
        self._records: list[dict[str, Any]] = []
        if self.path and self.path.exists():
            with self.path.open("r", encoding="utf-8") as handle:
                self._records = [json.loads(line) for line in handle if line.strip()]

    @staticmethod
    def _hash(record: dict[str, Any]) -> str:
        return sha256_json({key: value for key, value in record.items() if key != "record_hash"})

    def append(self, *, actor_id: str, action_type: str, object_ids: list[str], authorization_ref: str | None, result: str, policy_versions: list[str], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        record = {
            "record_id": new_id("aud"), "schema_version": "0.3.0", "sequence": len(self._records),
            "previous_hash": self._records[-1]["record_hash"] if self._records else None,
            "record_hash": "sha256:" + "0" * 64, "actor_id": actor_id, "action_type": action_type,
            "object_ids": object_ids, "occurred_at": utc_now(), "authorization_ref": authorization_ref,
            "result": result, "policy_versions": policy_versions, "metadata": metadata or {},
        }
        record["record_hash"] = self._hash(record)
        self.catalog.validate("audit-record", record)
        self._records.append(record)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        return copy.deepcopy(record)

    def verify(self) -> None:
        previous = None
        for sequence, record in enumerate(self._records):
            if record.get("sequence") != sequence or record.get("previous_hash") != previous or record.get("record_hash") != self._hash(record):
                raise ANOError("AUDIT_INTEGRITY_FAILURE", f"audit chain invalid at sequence {sequence}")
            previous = record["record_hash"]

    def query(self, *, object_id: str | None = None, actor_id: str | None = None) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(item) for item in self._records if (object_id is None or object_id in item["object_ids"]) and (actor_id is None or actor_id == item["actor_id"]))
