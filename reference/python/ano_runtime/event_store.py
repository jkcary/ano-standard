from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Callable, Generic, Iterable, TypeVar

from .errors import ANOError
from .util import parse_timestamp

T = TypeVar("T")


class AppendOnlyEventStore(Generic[T]):
    """Append-only JSONL event store suitable for tests and examples."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._events: list[dict[str, object]] = []
        self._event_ids: set[str] = set()
        if self.path is not None and self.path.exists():
            self._load()

    def _load(self) -> None:
        assert self.path is not None
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ANOError(
                        "INTEGRITY_FAILURE",
                        f"invalid event JSON at line {line_number}",
                    ) from exc
                self._append_memory(event)

    def _append_memory(self, event: dict[str, object]) -> None:
        event_id = str(event.get("event_id", ""))
        if not event_id:
            raise ANOError("SCHEMA_INVALID", "event_id is required")
        if event_id in self._event_ids:
            raise ANOError("DUPLICATE_EVENT_ID", f"event_id already exists: {event_id}")
        self._events.append(copy.deepcopy(event))
        self._event_ids.add(event_id)

    def append(self, event: dict[str, object]) -> int:
        self._append_memory(event)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
                handle.write("\n")
                handle.flush()
        return len(self._events) - 1

    @property
    def position(self) -> int:
        return len(self._events) - 1

    def events(self) -> tuple[dict[str, object], ...]:
        return tuple(copy.deepcopy(self._events))

    def by_type(self, event_type: str) -> tuple[dict[str, object], ...]:
        return tuple(copy.deepcopy(item) for item in self._events if item.get("event_type") == event_type)

    def between(
        self,
        start: str,
        end: str,
        *,
        time_field: str = "event_time",
    ) -> tuple[dict[str, object], ...]:
        """Query event_time or observed_at explicitly; the two clocks are never conflated."""
        if time_field not in {"event_time", "observed_at", "recorded_at"}:
            raise ANOError("TIME_FIELD_INVALID", f"unsupported time field: {time_field}")
        lower = parse_timestamp(start)
        upper = parse_timestamp(end)
        if lower > upper:
            raise ANOError("TIME_RANGE_INVALID", "start must not be after end")
        matches = []
        for item in self._events:
            value = item.get(time_field)
            if isinstance(value, str) and lower <= parse_timestamp(value) <= upper:
                matches.append(copy.deepcopy(item))
        return tuple(matches)

    def replay(self, projector: Callable[[T, dict[str, object]], T], initial: T) -> T:
        state = initial
        for event in self._events:
            state = projector(state, copy.deepcopy(event))
        return state
