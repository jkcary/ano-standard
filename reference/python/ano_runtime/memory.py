from __future__ import annotations

import copy
from typing import Any

from .errors import ANOError
from .event_store import AppendOnlyEventStore
from .events import build_event
from .schema import SchemaCatalog
from .util import canonical_json, sha256_json


class PersistentMemoryStore:
    """Event-sourced memory projection with explicit conflict and deletion semantics."""

    def __init__(
        self,
        event_store: AppendOnlyEventStore,
        catalog: SchemaCatalog,
        *,
        actor_id: str = "ano_runtime",
    ) -> None:
        self.event_store = event_store
        self.catalog = catalog
        self.actor_id = actor_id
        self._memories: dict[str, dict[str, Any]] = {}
        self._conflict_reasons: dict[str, str] = {}
        self._rebuild()

    def _rebuild(self) -> None:
        self._memories = {}
        self._conflict_reasons = {}
        for event in self.event_store.events():
            payload = event.get("payload", {})
            if not isinstance(payload, dict):
                continue
            if event.get("event_type") == "memory.created":
                memory = payload.get("memory")
                if isinstance(memory, dict):
                    self._memories[str(memory["memory_id"])] = copy.deepcopy(memory)
            elif event.get("event_type") == "memory.disputed":
                reason = str(payload.get("resolution_reason", "CONFLICT_UNRESOLVED"))
                for memory_id in payload.get("memory_ids", []):
                    if memory_id in self._memories:
                        self._memories[memory_id]["status"] = "disputed"
                        conflicts = set(self._memories[memory_id].get("conflicts_with_ids", []))
                        conflicts.update(item for item in payload.get("memory_ids", []) if item != memory_id)
                        self._memories[memory_id]["conflicts_with_ids"] = sorted(conflicts)
                        self._conflict_reasons[memory_id] = reason
            elif event.get("event_type") == "memory.deleted":
                memory_id = str(payload.get("memory_id", ""))
                if memory_id in self._memories:
                    self._memories[memory_id]["status"] = "deleted"
                    self._memories[memory_id]["content"] = None

    def add(self, memory: dict[str, Any]) -> dict[str, Any]:
        candidate = copy.deepcopy(memory)
        self.catalog.validate("memory", candidate)
        memory_id = str(candidate["memory_id"])
        if memory_id in self._memories:
            raise ANOError("MEMORY_ID_EXISTS", f"memory already exists: {memory_id}")

        comparable = [
            item
            for item in self._memories.values()
            if item["subject_id"] == candidate["subject_id"]
            and item["memory_type"] == candidate["memory_type"]
            and item["status"] in {"active", "disputed"}
        ]
        for existing in comparable:
            if canonical_json(existing["content"]) == canonical_json(candidate["content"]):
                return copy.deepcopy(existing)

        created = build_event(
            "memory.created",
            self.actor_id,
            [str(candidate["subject_id"]), memory_id],
            {"memory": candidate},
            event_time=str(candidate["created_at"]),
        )
        self.catalog.validate("event", created)
        self.event_store.append(created)
        self._memories[memory_id] = candidate

        if comparable:
            conflict_ids = sorted([str(item["memory_id"]) for item in comparable] + [memory_id])
            dispute = build_event(
                "memory.disputed",
                self.actor_id,
                conflict_ids,
                {
                    "memory_ids": conflict_ids,
                    "resolution_reason": "SAME_SUBJECT_AND_TYPE_DIFFERENT_CONTENT",
                    "selection": None,
                },
                causation_id=str(created["event_id"]),
            )
            self.catalog.validate("event", dispute)
            self.event_store.append(dispute)
            self._rebuild()
        return self.get(memory_id, include_deleted=True)

    def delete(self, memory_id: str, *, reason: str) -> None:
        memory = self._memories.get(memory_id)
        if memory is None:
            raise ANOError("MEMORY_NOT_FOUND", f"unknown memory: {memory_id}")
        if memory["status"] == "deleted":
            return
        event = build_event(
            "memory.deleted",
            self.actor_id,
            [str(memory["subject_id"]), memory_id],
            {
                "memory_id": memory_id,
                "reason": reason,
                "deleted_content_hash": sha256_json(memory["content"]),
            },
        )
        self.catalog.validate("event", event)
        self.event_store.append(event)
        self._rebuild()

    def get(self, memory_id: str, *, include_deleted: bool = False) -> dict[str, Any]:
        memory = self._memories.get(memory_id)
        if memory is None or (memory["status"] == "deleted" and not include_deleted):
            raise ANOError("MEMORY_NOT_FOUND", f"unknown or deleted memory: {memory_id}")
        result = copy.deepcopy(memory)
        if memory_id in self._conflict_reasons:
            result["conflict_resolution_reason"] = self._conflict_reasons[memory_id]
        return result

    def active(self, *, subject_id: str | None = None) -> tuple[dict[str, Any], ...]:
        return tuple(
            copy.deepcopy(item)
            for item in self._memories.values()
            if item["status"] == "active" and (subject_id is None or item["subject_id"] == subject_id)
        )
