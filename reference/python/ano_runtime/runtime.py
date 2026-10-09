from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from .errors import ANOError
from .event_store import AppendOnlyEventStore
from .permissions import PermissionEngine
from .state_machine import StateMachine
from .util import new_id, parse_timestamp, sha256_json, utc_now

Tool = Callable[[dict[str, Any]], dict[str, Any]]
Verifier = Callable[[dict[str, Any], dict[str, Any]], bool]
StateVersionValidator = Callable[[dict[str, Any]], bool]
ActionValidator = Callable[[dict[str, Any]], None]


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, action_type: str, tool: Tool) -> None:
        if action_type in self._tools:
            raise ANOError("STATE_CONFLICT", f"tool already registered: {action_type}")
        self._tools[action_type] = tool

    def get(self, action_type: str) -> Tool:
        try:
            return self._tools[action_type]
        except KeyError as exc:
            raise ANOError("CAPABILITY_UNAVAILABLE", f"no tool for {action_type}") from exc


@dataclass
class ExecutionResult:
    action: dict[str, Any]
    observation: dict[str, Any] | None
    verification: dict[str, Any] | None
    idempotent_replay: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ActionRuntime:
    """ANO-C action pipeline with deterministic permission and state gates."""

    def __init__(
        self,
        *,
        event_store: AppendOnlyEventStore,
        permission_engine: PermissionEngine,
        tool_registry: ToolRegistry,
        action_machine: StateMachine,
        runtime_id: str = "runtime_reference_001",
        state_version_validator: StateVersionValidator | None = None,
        action_validator: ActionValidator | None = None,
    ) -> None:
        self.event_store = event_store
        self.permission_engine = permission_engine
        self.tool_registry = tool_registry
        self.action_machine = action_machine
        self.runtime_id = runtime_id
        self.state_version_validator = state_version_validator or (lambda _action: True)
        self.action_validator = action_validator
        self._verifiers: dict[str, Verifier] = {}
        self._results: dict[str, ExecutionResult] = {}
        self._kill_switch_active = False
        self._recover_results()

    @classmethod
    def with_standard_machine(
        cls,
        *,
        standard_root: str | Path,
        event_store: AppendOnlyEventStore,
        permission_engine: PermissionEngine,
        tool_registry: ToolRegistry,
        state_version_validator: StateVersionValidator | None = None,
    ) -> "ActionRuntime":
        machine_path = Path(standard_root) / "state-machines" / "v0.3.0" / "action.machine.json"
        from .schema import SchemaCatalog

        catalog = SchemaCatalog(Path(standard_root) / "schemas" / "v0.3.0")
        return cls(
            event_store=event_store,
            permission_engine=permission_engine,
            tool_registry=tool_registry,
            action_machine=StateMachine.from_file(machine_path),
            state_version_validator=state_version_validator,
            action_validator=lambda action: catalog.validate("action", action),
        )

    def register_verifier(self, method: str, verifier: Verifier) -> None:
        if method in self._verifiers:
            raise ANOError("STATE_CONFLICT", f"verifier already registered: {method}")
        self._verifiers[method] = verifier

    def activate_kill_switch(self) -> None:
        self._kill_switch_active = True

    def execute(self, action_contract: dict[str, Any]) -> ExecutionResult:
        action = copy.deepcopy(action_contract)
        idempotency_key = str(action.get("idempotency_key", ""))
        if idempotency_key in self._results:
            recovered = copy.deepcopy(self._results[idempotency_key])
            recovered.idempotent_replay = True
            return recovered
        if self._kill_switch_active:
            raise ANOError("KILL_SWITCH_ACTIVE", "new action execution is disabled")

        if action.get("status") != "proposed":
            raise ANOError("INVALID_STATE_TRANSITION", "new action must be proposed")
        if self.action_validator is None:
            raise ANOError("SCHEMA_VALIDATOR_MISSING", "action schema validator is required")
        self.action_validator(action)
        if not self.state_version_validator(action):
            raise ANOError("STATE_CONFLICT", "decision state version is stale")
        if sha256_json(action.get("parameters", {})) != action.get("parameters_hash"):
            raise ANOError("PARAMETER_MISMATCH", "parameters changed after decision")
        if parse_timestamp(str(action["timeout_at"])) <= parse_timestamp(utc_now()):
            raise ANOError("ACTION_TIMEOUT", "action timeout has already elapsed")
        tool = self.tool_registry.get(str(action["action_type"]))

        self._transition(action, "action.validated", {"schema_valid", "state_version_current"})
        self.permission_engine.authorize(action)
        self._transition(
            action,
            "action.authorized",
            {"permission_active", "parameters_match", "budget_available"},
        )

        # Recheck and consume immediately before crossing the side-effect boundary.
        self.permission_engine.authorize(action, consume=True)
        self._transition(
            action,
            "action.execution_started",
            {"permission_rechecked", "idempotency_reserved"},
        )

        try:
            tool_result = tool(copy.deepcopy(action["parameters"]))
        except TimeoutError:
            result = ExecutionResult(action=copy.deepcopy(action), observation=None, verification=None)
            self._transition(
                action,
                "action.result_unknown",
                {"outcome_unobservable"},
                extra_payload={"execution_result": result.as_dict()},
            )
            result.action = copy.deepcopy(action)
            self._results[idempotency_key] = copy.deepcopy(result)
            return result
        except Exception as exc:
            self._transition(action, "action.failed", set())
            raise ANOError("PERMANENT_TOOL_FAILURE", str(exc)) from exc

        self._transition(action, "action.executed", {"tool_returned"})
        observation = self._observation(action, tool_result)
        self._transition(action, "action.observed", {"observation_present"})

        verifier = self._verifiers.get(str(action["verification_method"]))
        if verifier is None:
            self._transition(action, "action.failed", {"verification_failed"})
            raise ANOError("VERIFICATION_FAILED", "verification method is not registered")
        passed = bool(verifier(copy.deepcopy(action), copy.deepcopy(observation)))
        verification = self._verification(action, observation, passed)
        if not passed:
            self._transition(action, "action.failed", {"verification_failed"})
            return ExecutionResult(action=action, observation=observation, verification=verification)

        self._transition(action, "action.verified", {"verification_passed"})
        result = ExecutionResult(action=action, observation=observation, verification=verification)
        self._transition(
            action,
            "action.completed",
            {"action_success_only"},
            extra_payload={"execution_result": result.as_dict()},
        )
        result.action = copy.deepcopy(action)
        self._results[idempotency_key] = copy.deepcopy(result)
        return result

    def _transition(
        self,
        action: dict[str, Any],
        event_name: str,
        guards: set[str],
        *,
        extra_payload: dict[str, Any] | None = None,
    ) -> None:
        previous = str(action["status"])
        current = self.action_machine.transition(previous, event_name, guards)
        action["status"] = current
        action["version"] = int(action.get("version", 0)) + 1
        payload: dict[str, Any] = {
            "action_id": action["action_id"],
            "from": previous,
            "to": current,
            "action_version": action["version"],
            "idempotency_key": action["idempotency_key"],
        }
        if extra_payload:
            payload.update(copy.deepcopy(extra_payload))
        if isinstance(payload.get("execution_result"), dict):
            payload["execution_result"]["action"] = copy.deepcopy(action)
        self.event_store.append(self._event(event_name, action, payload))

    def _event(self, event_type: str, action: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        return {
            "event_id": new_id("evt"),
            "event_type": event_type,
            "schema_version": "0.3.0",
            "actor_id": self.runtime_id,
            "subject_ids": [action["action_id"]],
            "event_time": now,
            "observed_at": now,
            "recorded_at": now,
            "payload": payload,
            "epistemic_status": "observed",
            "confidence": 1.0,
            "sensitivity": "internal",
            "provenance": {
                "source_type": "system",
                "source_id": self.runtime_id,
                "parent_ids": [action["decision_id"]],
                "observed_at": now,
            },
            "correlation_id": action["action_id"],
            "causation_id": action["decision_id"],
        }

    @staticmethod
    def _observation(action: dict[str, Any], tool_result: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        result = copy.deepcopy(tool_result.get("result", {}))
        return {
            "observation_id": new_id("obs"),
            "schema_version": "0.3.0",
            "action_id": action["action_id"],
            "observer_id": str(tool_result.get("observer_id", "tool_adapter_unknown")),
            "observed_at": now,
            "result_code": str(tool_result.get("result_code", "UNKNOWN")),
            "result": result,
            "raw_evidence_ref": str(tool_result.get("raw_evidence_ref", f"artifact://evidence/{action['action_id']}")),
            "integrity_hash": sha256_json(tool_result),
            "confidence": float(tool_result.get("confidence", 1.0)),
        }

    @staticmethod
    def _verification(
        action: dict[str, Any], observation: dict[str, Any], passed: bool
    ) -> dict[str, Any]:
        return {
            "verification_id": new_id("ver"),
            "schema_version": "0.3.0",
            "subject_type": "action",
            "subject_id": action["action_id"],
            "criterion": action["expected_result"],
            "method": action["verification_method"],
            "evidence_ids": [observation["observation_id"]],
            "result": "passed" if passed else "failed",
            "verifier_id": "verifier_reference_runtime",
            "verified_at": utc_now(),
        }

    def _recover_results(self) -> None:
        recoverable = (
            *self.event_store.by_type("action.completed"),
            *self.event_store.by_type("action.result_unknown"),
        )
        for event in recoverable:
            payload = event.get("payload", {})
            if not isinstance(payload, dict):
                continue
            stored = payload.get("execution_result")
            key = payload.get("idempotency_key")
            if isinstance(stored, dict) and isinstance(key, str):
                self._results[key] = ExecutionResult(
                    action=copy.deepcopy(stored["action"]),
                    observation=copy.deepcopy(stored.get("observation")),
                    verification=copy.deepcopy(stored.get("verification")),
                    idempotent_replay=False,
                )
