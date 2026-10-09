from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .errors import ANOError


@dataclass(frozen=True)
class WorkItem:
    work_id: str
    priority: float
    enqueued_at: datetime
    payload: dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    parent_id: str | None = None


class BoundedWorkQueue:
    """A bounded priority queue with aging, recursion, and per-parent fan-out limits."""

    def __init__(
        self,
        *,
        max_size: int,
        max_depth: int,
        max_fanout: int,
        aging_per_second: float = 0.01,
    ) -> None:
        if min(max_size, max_depth, max_fanout) < 1:
            raise ValueError("queue limits must be positive")
        self.max_size = max_size
        self.max_depth = max_depth
        self.max_fanout = max_fanout
        self.aging_per_second = aging_per_second
        self._items: list[WorkItem] = []
        self._fanout: dict[str, int] = {}

    def enqueue(self, item: WorkItem) -> None:
        if len(self._items) >= self.max_size:
            raise ANOError("BACKPRESSURE", "work queue capacity reached", retryable=True)
        if item.depth > self.max_depth:
            raise ANOError("RECURSION_LIMIT", f"depth {item.depth} exceeds {self.max_depth}")
        if not 0 <= item.priority <= 1:
            raise ANOError("PRIORITY_INVALID", "priority must be between 0 and 1")
        if item.parent_id is not None:
            count = self._fanout.get(item.parent_id, 0)
            if count >= self.max_fanout:
                raise ANOError("FANOUT_LIMIT", f"parent {item.parent_id} exceeded fan-out")
            self._fanout[item.parent_id] = count + 1
        self._items.append(copy.deepcopy(item))

    def pop(self, *, now: datetime | None = None) -> WorkItem:
        if not self._items:
            raise ANOError("QUEUE_EMPTY", "work queue is empty")
        current = now or datetime.now(timezone.utc)

        def score(item: WorkItem) -> tuple[float, float]:
            age = max(0.0, (current - item.enqueued_at).total_seconds())
            return (item.priority + age * self.aging_per_second, -item.enqueued_at.timestamp())

        selected = max(self._items, key=score)
        self._items.remove(selected)
        return selected

    def __len__(self) -> int:
        return len(self._items)
