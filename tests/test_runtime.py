from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

from ano_runtime import (
    ANOError,
    ActionRuntime,
    AppendOnlyEventStore,
    PermissionEngine,
    SchemaCatalog,
    ToolRegistry,
    sha256_json,
)

from tests.support import STANDARD_ROOT, conformance, fresh_action, fresh_grant, load_example


class ActionRuntimeConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")

    def make_runtime(
        self,
        *,
        event_path: Path | None = None,
        tool: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        register_grant: bool = True,
    ) -> tuple[ActionRuntime, AppendOnlyEventStore, PermissionEngine]:
        store = AppendOnlyEventStore(event_path)
        permissions = PermissionEngine()
        if register_grant:
            permissions.register(fresh_grant())
        tools = ToolRegistry()
        tools.register(
            "demo.send",
            tool
            or (
                lambda _parameters: {
                    "result_code": "ACCEPTED",
                    "observer_id": "tool_demo_sender",
                    "result": {"provider_message_id": "msg_runtime_001"},
                    "confidence": 1.0,
                }
            ),
        )
        runtime = ActionRuntime.with_standard_machine(
            standard_root=STANDARD_ROOT,
            event_store=store,
            permission_engine=permissions,
            tool_registry=tools,
        )
        runtime.register_verifier(
            "result_code_equals_accepted",
            lambda _action, observation: observation["result_code"] == "ACCEPTED",
        )
        return runtime, store, permissions

    @conformance("C-ACT-001")
    def test_completed_action_has_auditable_transition_chain(self) -> None:
        runtime, store, _permissions = self.make_runtime()
        result = runtime.execute(fresh_action())
        self.assertEqual("completed", result.action["status"])
        transitions = store.events()
        self.assertEqual(
            [
                "action.validated",
                "action.authorized",
                "action.execution_started",
                "action.executed",
                "action.observed",
                "action.verified",
                "action.completed",
            ],
            [event["event_type"] for event in transitions],
        )
        for event in transitions:
            self.catalog.validate("event", event)
            self.assertEqual(result.action["action_id"], event["correlation_id"])
        self.catalog.validate("action", result.action)
        self.catalog.validate("observation", result.observation)
        self.catalog.validate("verification", result.verification)

    @conformance("C-PERM-001")
    def test_missing_grant_fails_closed(self) -> None:
        runtime, _store, _permissions = self.make_runtime(register_grant=False)
        with self.assertRaises(ANOError) as raised:
            runtime.execute(fresh_action())
        self.assertEqual("AUTH_MISSING", raised.exception.code)

    @conformance("C-PERM-002")
    def test_parameter_change_after_decision_is_rejected(self) -> None:
        runtime, _store, _permissions = self.make_runtime()
        action = fresh_action()
        action["parameters"]["message"] = "Changed after approval"
        with self.assertRaises(ANOError) as raised:
            runtime.execute(action)
        self.assertEqual("PARAMETER_MISMATCH", raised.exception.code)

    @conformance("C-PERM-003")
    def test_resource_outside_scope_is_rejected(self) -> None:
        runtime, _store, _permissions = self.make_runtime()
        action = fresh_action()
        action["parameters"]["recipient"] = "other@example.com"
        action["parameters_hash"] = sha256_json(action["parameters"])
        with self.assertRaises(ANOError) as raised:
            runtime.execute(action)
        self.assertEqual("POLICY_DENIED", raised.exception.code)

    @conformance("C-CON-001")
    def test_revocation_wins_before_execution(self) -> None:
        runtime, _store, permissions = self.make_runtime()
        permissions.revoke("grant_demo_001", expected_version=1)
        with self.assertRaises(ANOError) as raised:
            runtime.execute(fresh_action())
        self.assertEqual("AUTH_REVOKED", raised.exception.code)

    @conformance("C-VER-001")
    def test_action_success_does_not_complete_goal(self) -> None:
        runtime, _store, _permissions = self.make_runtime()
        goal = load_example("goal")
        result = runtime.execute(fresh_action())
        self.assertEqual("completed", result.action["status"])
        self.assertEqual("active", goal["status"])

    @conformance("C-ACT-002")
    def test_unknown_side_effect_is_not_blindly_retried(self) -> None:
        calls = 0

        def timeout_tool(_parameters: dict[str, Any]) -> dict[str, Any]:
            nonlocal calls
            calls += 1
            raise TimeoutError("connection lost after submit")

        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "events.jsonl"
            runtime, _store, _permissions = self.make_runtime(
                event_path=event_path, tool=timeout_tool
            )
            action = fresh_action()
            first = runtime.execute(action)

            restarted, _store2, _permissions2 = self.make_runtime(
                event_path=event_path, tool=timeout_tool
            )
            second = restarted.execute(action)
            self.assertEqual("unknown", first.action["status"])
            self.assertTrue(second.idempotent_replay)
            self.assertEqual(1, calls)

    @conformance("C-REC-001")
    def test_completed_side_effect_is_not_repeated_after_restart(self) -> None:
        calls = 0

        def counted_tool(_parameters: dict[str, Any]) -> dict[str, Any]:
            nonlocal calls
            calls += 1
            return {
                "result_code": "ACCEPTED",
                "observer_id": "tool_demo_sender",
                "result": {"provider_message_id": "msg_once"},
            }

        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "events.jsonl"
            first_runtime, _store, _permissions = self.make_runtime(
                event_path=event_path, tool=counted_tool
            )
            action = fresh_action()
            first_runtime.execute(action)

            second_runtime, _store2, _permissions2 = self.make_runtime(
                event_path=event_path, tool=counted_tool
            )
            replayed = second_runtime.execute(action)
            self.assertTrue(replayed.idempotent_replay)
            self.assertEqual("completed", replayed.action["status"])
            self.assertEqual(1, calls)

    @conformance("C-CTRL-001")
    def test_kill_switch_blocks_new_action_without_model(self) -> None:
        runtime, _store, _permissions = self.make_runtime()
        runtime.activate_kill_switch()
        with self.assertRaises(ANOError) as raised:
            runtime.execute(fresh_action())
        self.assertEqual("KILL_SWITCH_ACTIVE", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
