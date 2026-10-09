from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .errors import ANOError, InvalidTransition


@dataclass(frozen=True)
class Transition:
    source: str
    event: str
    target: str
    guards: tuple[str, ...]


class StateMachine:
    def __init__(self, definition: Mapping[str, object]) -> None:
        self.machine_id = str(definition["machine_id"])
        self.initial_state = str(definition["initial_state"])
        self.states = frozenset(str(item) for item in definition["states"])
        self.terminal_states = frozenset(str(item) for item in definition["terminal_states"])
        self.transitions = tuple(
            Transition(
                source=str(item["from"]),
                event=str(item["event"]),
                target=str(item["to"]),
                guards=tuple(str(guard) for guard in item["guards"]),
            )
            for item in definition["transitions"]
        )
        self._validate_definition()

    @classmethod
    def from_file(cls, path: str | Path) -> "StateMachine":
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    def _validate_definition(self) -> None:
        if self.initial_state not in self.states:
            raise ANOError("INVALID_STATE_MACHINE", "initial state is not declared")
        if not self.terminal_states <= self.states:
            raise ANOError("INVALID_STATE_MACHINE", "terminal state is not declared")
        seen: set[tuple[str, str]] = set()
        for transition in self.transitions:
            if transition.source not in self.states or transition.target not in self.states:
                raise ANOError("INVALID_STATE_MACHINE", "transition uses undeclared state")
            key = (transition.source, transition.event)
            if key in seen:
                raise ANOError("INVALID_STATE_MACHINE", f"ambiguous transition {key}")
            seen.add(key)

    def transition(self, current: str, event: str, satisfied_guards: Iterable[str] = ()) -> str:
        if current in self.terminal_states:
            raise ANOError("TERMINAL_STATE", f"state {current!r} is terminal")
        match = next(
            (item for item in self.transitions if item.source == current and item.event == event),
            None,
        )
        if match is None:
            raise InvalidTransition(current, event)
        satisfied = set(satisfied_guards)
        missing = set(match.guards) - satisfied
        if missing:
            raise ANOError("GUARD_FAILED", f"missing guards: {sorted(missing)}")
        return match.target

