from __future__ import annotations

import json
import unittest

from ano_runtime import ANOError, SchemaCatalog, StateMachine

from tests.support import STANDARD_ROOT, conformance


class StateMachineConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")
        cls.machine_dir = STANDARD_ROOT / "state-machines" / "v0.3.0"

    @conformance("C-SM-001")
    def test_machine_definitions_are_valid_and_unambiguous(self) -> None:
        for path in sorted(self.machine_dir.glob("*.machine.json")):
            with self.subTest(machine=path.name):
                with path.open("r", encoding="utf-8") as handle:
                    definition = json.load(handle)
                self.catalog.validate("state-machine", definition)
                StateMachine(definition)

    @conformance("C-ACT-003")
    def test_action_cannot_jump_from_proposed_to_completed(self) -> None:
        machine = StateMachine.from_file(self.machine_dir / "action.machine.json")
        with self.assertRaises(ANOError):
            machine.transition("proposed", "action.completed", {"action_success_only"})

    @conformance("C-ACT-004")
    def test_action_authorization_requires_all_guards(self) -> None:
        machine = StateMachine.from_file(self.machine_dir / "action.machine.json")
        with self.assertRaises(ANOError) as raised:
            machine.transition("validated", "action.authorized", {"permission_active"})
        self.assertEqual("GUARD_FAILED", raised.exception.code)

    @conformance("C-ID-002")
    def test_terminated_identity_is_terminal(self) -> None:
        machine = StateMachine.from_file(self.machine_dir / "identity.machine.json")
        with self.assertRaises(ANOError) as raised:
            machine.transition("terminated", "identity.resumed", set())
        self.assertEqual("TERMINAL_STATE", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
