from __future__ import annotations

import copy
import hashlib
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

from .errors import ANOError
from .event_store import AppendOnlyEventStore
from .events import build_event
from .schema import SchemaCatalog
from .state_machine import StateMachine
from .util import parse_timestamp, utc_now


class CommitmentService:
    """Authoritative event-sourced commitment projection."""

    def __init__(
        self,
        event_store: AppendOnlyEventStore,
        catalog: SchemaCatalog,
        machine_path: str | Path,
        *,
        actor_id: str = "ano_runtime",
    ) -> None:
        self.event_store = event_store
        self.catalog = catalog
        self.machine = StateMachine.from_file(machine_path)
        self.actor_id = actor_id
        self._commitments: dict[str, dict[str, Any]] = {}
        self._rebuild()

    def _rebuild(self) -> None:
        self._commitments = {}
        for event in self.event_store.events():
            if event.get("event_type") not in {"commitment.created", "commitment.transitioned"}:
                continue
            payload = event.get("payload", {})
            commitment = payload.get("commitment") if isinstance(payload, dict) else None
            if isinstance(commitment, dict):
                self._commitments[str(commitment["commitment_id"])] = copy.deepcopy(commitment)

    def create(self, commitment: dict[str, Any]) -> dict[str, Any]:
        candidate = copy.deepcopy(commitment)
        self.catalog.validate("commitment", candidate)
        if candidate["status"] != self.machine.initial_state:
            raise ANOError("INVALID_INITIAL_STATE", "new commitments must start as proposed")
        commitment_id = str(candidate["commitment_id"])
        if commitment_id in self._commitments:
            raise ANOError("COMMITMENT_ID_EXISTS", f"commitment already exists: {commitment_id}")
        event = build_event(
            "commitment.created",
            self.actor_id,
            [str(candidate["promisor_id"]), str(candidate["beneficiary_id"]), commitment_id],
            {"commitment": candidate},
            event_time=None,
        )
        self.catalog.validate("event", event)
        self.event_store.append(event)
        self._commitments[commitment_id] = candidate
        return copy.deepcopy(candidate)

    def transition(
        self,
        commitment_id: str,
        event_type: str,
        guards: Iterable[str],
        *,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        current = self.get(commitment_id)
        target = self.machine.transition(str(current["status"]), event_type, guards)
        updated = copy.deepcopy(current)
        updated["status"] = target
        updated["version"] = int(updated["version"]) + 1
        self.catalog.validate("commitment", updated)
        event = build_event(
            "commitment.transitioned",
            self.actor_id,
            [str(updated["promisor_id"]), str(updated["beneficiary_id"]), commitment_id],
            {"transition": event_type, "commitment": updated, "evidence": evidence or {}},
        )
        self.catalog.validate("event", event)
        self.event_store.append(event)
        self._commitments[commitment_id] = updated
        return copy.deepcopy(updated)

    def get(self, commitment_id: str) -> dict[str, Any]:
        try:
            return copy.deepcopy(self._commitments[commitment_id])
        except KeyError as exc:
            raise ANOError("COMMITMENT_NOT_FOUND", f"unknown commitment: {commitment_id}") from exc

    def all(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(item) for item in self._commitments.values())


class PersistentScheduler:
    """Durable time-trigger dispatcher with stable idempotency and breach forecasts."""

    def __init__(
        self,
        commitments: CommitmentService,
        *,
        on_trigger: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.commitments = commitments
        self.event_store = commitments.event_store
        self.catalog = commitments.catalog
        self.on_trigger = on_trigger

    @staticmethod
    def trigger_id(commitment: dict[str, Any]) -> str:
        material = f"{commitment['commitment_id']}|{commitment['due_at']}|{commitment['trigger']['type']}|{commitment['trigger']['expression']}"
        return "trg_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]

    def _emitted_trigger_ids(self) -> set[str]:
        return {
            str(event["payload"]["trigger_id"])
            for event in self.event_store.by_type("schedule.triggered")
            if isinstance(event.get("payload"), dict) and "trigger_id" in event["payload"]
        }

    def process_due(self, *, now: str | None = None) -> tuple[str, ...]:
        current_time = parse_timestamp(now or utc_now())
        emitted = self._emitted_trigger_ids()
        dispatched: list[str] = []
        for commitment in self.commitments.all():
            if commitment["status"] != "scheduled" or parse_timestamp(str(commitment["due_at"])) > current_time:
                continue
            trigger_id = self.trigger_id(commitment)
            if trigger_id in emitted:
                self.commitments.transition(
                    str(commitment["commitment_id"]),
                    "commitment.activated",
                    {"trigger_claimed"},
                    evidence={"trigger_id": trigger_id, "recovered": True},
                )
                continue
            event = build_event(
                "schedule.triggered",
                self.commitments.actor_id,
                [str(commitment["commitment_id"])],
                {"trigger_id": trigger_id, "commitment_id": commitment["commitment_id"]},
                event_time=str(commitment["due_at"]),
            )
            self.catalog.validate("event", event)
            self.event_store.append(event)
            self.commitments.transition(
                str(commitment["commitment_id"]),
                "commitment.activated",
                {"trigger_claimed"},
                evidence={"trigger_id": trigger_id},
            )
            dispatched.append(trigger_id)
            if self.on_trigger is not None:
                self.on_trigger(copy.deepcopy(event))
        return tuple(dispatched)

    def forecast_breaches(
        self,
        *,
        now: str | None = None,
        horizon: timedelta = timedelta(hours=1),
    ) -> tuple[str, ...]:
        current_time = parse_timestamp(now or utc_now())
        existing = {
            str(event["payload"]["commitment_id"])
            for event in self.event_store.by_type("commitment.breach_forecast")
            if isinstance(event.get("payload"), dict) and "commitment_id" in event["payload"]
        }
        forecasts: list[str] = []
        for commitment in self.commitments.all():
            commitment_id = str(commitment["commitment_id"])
            if commitment_id in existing or commitment["status"] not in {"blocked", "scheduled"}:
                continue
            remaining = parse_timestamp(str(commitment["due_at"])) - current_time
            if remaining > horizon:
                continue
            event = build_event(
                "commitment.breach_forecast",
                self.commitments.actor_id,
                [commitment_id, str(commitment["beneficiary_id"])],
                {
                    "commitment_id": commitment_id,
                    "status": commitment["status"],
                    "due_at": commitment["due_at"],
                    "reason": "DEADLINE_AT_RISK",
                    "escalation_policy_id": commitment["escalation_policy_id"],
                },
            )
            self.catalog.validate("event", event)
            self.event_store.append(event)
            forecasts.append(commitment_id)
        return tuple(forecasts)
