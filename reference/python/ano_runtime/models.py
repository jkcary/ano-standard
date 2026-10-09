from __future__ import annotations

import copy
from typing import Any, Callable

from .errors import ANOError

ModelValidator = Callable[[dict[str, Any]], None]


class ModelRegistry:
    """Model-independent adapter registry with explicit safe degradation."""

    def __init__(self, validator: ModelValidator) -> None:
        self.validator = validator
        self._adapters: dict[str, dict[str, Any]] = {}
        self._active_id: str | None = None

    def register(self, adapter: dict[str, Any]) -> None:
        self.validator(adapter)
        adapter_id = str(adapter["adapter_id"])
        if adapter_id in self._adapters:
            raise ANOError("STATE_CONFLICT", f"adapter already exists: {adapter_id}")
        self._adapters[adapter_id] = copy.deepcopy(adapter)
        if adapter.get("status") == "active":
            if self._active_id is not None:
                raise ANOError("STATE_CONFLICT", "multiple active adapters are not allowed per role")
            self._active_id = adapter_id

    def activate(self, adapter_id: str) -> dict[str, Any]:
        candidate = self._adapters.get(adapter_id)
        if candidate is None:
            raise ANOError("MODEL_UNAVAILABLE", f"unknown adapter: {adapter_id}")
        if candidate["status"] not in {"candidate", "approved", "active"}:
            raise ANOError("MODEL_UNAVAILABLE", f"adapter cannot be activated: {candidate['status']}")
        if self._active_id and self._active_id != adapter_id:
            self._adapters[self._active_id]["status"] = "approved"
        candidate["status"] = "active"
        self._active_id = adapter_id
        return copy.deepcopy(candidate)

    def degrade_active(self) -> dict[str, Any] | None:
        if self._active_id is not None:
            self._adapters[self._active_id]["status"] = "degraded"
            self._active_id = None
        fallback = next(
            (
                adapter
                for adapter in self._adapters.values()
                if adapter["status"] == "approved"
            ),
            None,
        )
        if fallback is None:
            return None
        return self.activate(str(fallback["adapter_id"]))

    def active(self) -> dict[str, Any] | None:
        if self._active_id is None:
            return None
        return copy.deepcopy(self._adapters[self._active_id])

