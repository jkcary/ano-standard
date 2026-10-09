from __future__ import annotations

import copy
import unittest

from ano_runtime import ANOError, AppendOnlyEventStore

from tests.support import conformance, load_example


class EventStoreConformanceTests(unittest.TestCase):
    @conformance("C-EVT-001")
    def test_correction_appends_without_overwriting_original(self) -> None:
        store = AppendOnlyEventStore()
        original = load_example("event")
        store.append(original)
        correction = copy.deepcopy(original)
        correction["event_id"] = "evt_demo_002"
        correction["event_type"] = "event.corrected"
        correction["causation_id"] = original["event_id"]
        correction["provenance"]["parent_ids"] = [original["event_id"]]
        correction["payload"] = {"corrects_event_id": original["event_id"]}
        store.append(correction)

        events = store.events()
        self.assertEqual(2, len(events))
        self.assertEqual("user.goal_declared", events[0]["event_type"])
        self.assertEqual(original["event_id"], events[1]["causation_id"])

    @conformance("C-EVT-002")
    def test_duplicate_event_identifier_is_rejected(self) -> None:
        store = AppendOnlyEventStore()
        event = load_example("event")
        store.append(event)
        with self.assertRaises(ANOError) as raised:
            store.append(event)
        self.assertEqual("DUPLICATE_EVENT_ID", raised.exception.code)

    @conformance("C-STATE-001")
    def test_projection_is_rebuilt_from_event_order(self) -> None:
        store = AppendOnlyEventStore()
        first = load_example("event")
        second = copy.deepcopy(first)
        second["event_id"] = "evt_demo_002"
        second["event_type"] = "goal.cancelled"
        second["causation_id"] = first["event_id"]
        second["payload"] = {"status": "cancelled"}
        store.append(first)
        store.append(second)

        def projector(state: dict[str, str], event: dict[str, object]) -> dict[str, str]:
            updated = dict(state)
            if event["event_type"] == "user.goal_declared":
                updated["goal_demo_001"] = "active"
            if event["event_type"] == "goal.cancelled":
                updated["goal_demo_001"] = "cancelled"
            return updated

        rebuilt = store.replay(projector, {})
        self.assertEqual({"goal_demo_001": "cancelled"}, rebuilt)


if __name__ == "__main__":
    unittest.main()

