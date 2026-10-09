from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ano_runtime import (
    ANOError,
    AppendOnlyEventStore,
    BoundedWorkQueue,
    CommitmentService,
    PersistentMemoryStore,
    PersistentScheduler,
    SchemaCatalog,
    WorkItem,
    build_event,
)

from tests.support import STANDARD_ROOT, conformance, fresh_commitment, fresh_memory


class PersistentProfileConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")
        cls.commitment_machine = STANDARD_ROOT / "state-machines" / "v0.3.0" / "commitment.machine.json"

    @conformance("P-TIME-001")
    def test_event_and_observation_time_are_queried_independently(self) -> None:
        store = AppendOnlyEventStore()
        event = build_event(
            "world.fact_observed",
            "ano_runtime",
            ["subject_demo"],
            {"value": 1},
            event_time="2020-01-01T00:00:00Z",
        )
        self.catalog.validate("event", event)
        store.append(event)
        observed = datetime.fromisoformat(str(event["observed_at"]).replace("Z", "+00:00"))
        observed_start = (observed - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        observed_end = (observed + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")

        self.assertEqual(0, len(store.between(observed_start, observed_end, time_field="event_time")))
        self.assertEqual(1, len(store.between(observed_start, observed_end, time_field="observed_at")))

    @conformance("P-MEM-001")
    def test_conflicting_memories_remain_disputed_with_visible_reason(self) -> None:
        store = PersistentMemoryStore(AppendOnlyEventStore(), self.catalog)
        first = fresh_memory("mem_conflict_001")
        second = fresh_memory("mem_conflict_002")
        second["content"] = "User prefers detailed technical reports."
        store.add(first)
        store.add(second)

        rebuilt_first = store.get("mem_conflict_001")
        rebuilt_second = store.get("mem_conflict_002")
        self.assertEqual("disputed", rebuilt_first["status"])
        self.assertEqual("disputed", rebuilt_second["status"])
        self.assertIn("mem_conflict_002", rebuilt_first["conflicts_with_ids"])
        self.assertEqual("SAME_SUBJECT_AND_TYPE_DIFFERENT_CONTENT", rebuilt_first["conflict_resolution_reason"])

    @conformance("P-MEM-002")
    def test_deleted_memory_content_does_not_reappear_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory-events.jsonl"
            first_runtime = PersistentMemoryStore(AppendOnlyEventStore(path), self.catalog)
            first_runtime.add(fresh_memory("mem_delete_001"))
            first_runtime.delete("mem_delete_001", reason="DATA_SUBJECT_REQUEST")

            restarted = PersistentMemoryStore(AppendOnlyEventStore(path), self.catalog)
            with self.assertRaises(ANOError):
                restarted.get("mem_delete_001")
            tombstone = restarted.get("mem_delete_001", include_deleted=True)
            self.assertEqual("deleted", tombstone["status"])
            self.assertIsNone(tombstone["content"])

    def _scheduled_service(self, path: Path, commitment_id: str = "com_restart_001") -> CommitmentService:
        service = CommitmentService(AppendOnlyEventStore(path), self.catalog, self.commitment_machine)
        if not service.all():
            commitment = fresh_commitment(commitment_id)
            service.create(commitment)
            service.transition(
                commitment_id,
                "commitment.accepted",
                {"promisor_assigned", "trigger_present", "completion_condition_present", "capability_available"},
            )
            service.transition(commitment_id, "commitment.scheduled", {"schedule_persisted"})
        return service

    @conformance("P-COM-001")
    def test_commitment_survives_restart_and_continues_scheduling_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commitment-events.jsonl"
            first = self._scheduled_service(path)
            before = first.get("com_restart_001")
            restarted = CommitmentService(AppendOnlyEventStore(path), self.catalog, self.commitment_machine)
            after = restarted.get("com_restart_001")
            self.assertEqual(before, after)
            self.assertEqual(1, len(restarted.all()))
            deliveries: list[str] = []
            PersistentScheduler(
                restarted,
                on_trigger=lambda event: deliveries.append(str(event["payload"]["trigger_id"])),
            ).process_due()
            restarted_again = CommitmentService(AppendOnlyEventStore(path), self.catalog, self.commitment_machine)
            PersistentScheduler(
                restarted_again,
                on_trigger=lambda event: deliveries.append("duplicate"),
            ).process_due()
            self.assertEqual(1, len(deliveries))
            self.assertEqual("active", restarted_again.get("com_restart_001")["status"])

    @conformance("P-SCH-001")
    def test_restarted_scheduler_suppresses_duplicate_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scheduler-events.jsonl"
            service = self._scheduled_service(path, "com_schedule_001")
            delivered: list[str] = []
            scheduler = PersistentScheduler(service, on_trigger=lambda event: delivered.append(str(event["payload"]["trigger_id"])))
            scheduler.process_due()

            restarted_service = CommitmentService(AppendOnlyEventStore(path), self.catalog, self.commitment_machine)
            restarted_scheduler = PersistentScheduler(restarted_service, on_trigger=lambda event: delivered.append("duplicate"))
            restarted_scheduler.process_due()
            self.assertEqual(1, len(delivered))
            self.assertEqual(1, len(restarted_service.event_store.by_type("schedule.triggered")))
            self.assertEqual("active", restarted_service.get("com_schedule_001")["status"])

    @conformance("P-COM-002")
    def test_breach_is_forecast_before_deadline_without_false_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "forecast-events.jsonl"
            service = self._scheduled_service(path, "com_forecast_001")
            service.transition(
                "com_forecast_001",
                "commitment.blocked",
                {"block_reason_recorded", "review_time_set"},
                evidence={"reason": "WAITING_FOR_PERMISSION", "review_at": "2026-08-27T18:00:00Z"},
            )
            commitment = service.get("com_forecast_001")
            now = (datetime.fromisoformat(commitment["due_at"].replace("Z", "+00:00")) - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
            scheduler = PersistentScheduler(service)
            self.assertEqual(("com_forecast_001",), scheduler.forecast_breaches(now=now))
            self.assertEqual((), scheduler.forecast_breaches(now=now))
            self.assertEqual("blocked", service.get("com_forecast_001")["status"])

    @conformance("P-LIVE-001")
    def test_aging_prevents_starvation_and_capacity_applies_backpressure(self) -> None:
        now = datetime.now(timezone.utc)
        queue = BoundedWorkQueue(max_size=2, max_depth=3, max_fanout=2, aging_per_second=0.02)
        queue.enqueue(WorkItem("old_low", 0.1, now - timedelta(minutes=2)))
        queue.enqueue(WorkItem("new_high", 0.9, now))
        with self.assertRaises(ANOError) as raised:
            queue.enqueue(WorkItem("overflow", 1.0, now))
        self.assertEqual("BACKPRESSURE", raised.exception.code)
        self.assertEqual("old_low", queue.pop(now=now).work_id)

    @conformance("P-LOOP-001")
    def test_recursion_and_fanout_are_bounded(self) -> None:
        now = datetime.now(timezone.utc)
        queue = BoundedWorkQueue(max_size=10, max_depth=2, max_fanout=2)
        queue.enqueue(WorkItem("child_1", 0.5, now, depth=1, parent_id="root"))
        queue.enqueue(WorkItem("child_2", 0.5, now, depth=1, parent_id="root"))
        with self.assertRaises(ANOError) as fanout:
            queue.enqueue(WorkItem("child_3", 0.5, now, depth=1, parent_id="root"))
        self.assertEqual("FANOUT_LIMIT", fanout.exception.code)
        with self.assertRaises(ANOError) as recursion:
            queue.enqueue(WorkItem("too_deep", 0.5, now, depth=3))
        self.assertEqual("RECURSION_LIMIT", recursion.exception.code)


if __name__ == "__main__":
    unittest.main()
