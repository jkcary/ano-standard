from __future__ import annotations

import tempfile
import json
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ano_runtime import (
    ANOError,
    DistributedOperationStoreAdapter,
    PostgresDistributedAdapterPlan,
    SchemaCatalog,
    SqliteDistributedOperationStore,
)

from tests.support import STANDARD_ROOT, conformance


class DistributedDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.5.0")
        self.now = datetime.now(timezone.utc)

    def store(self, path: Path) -> SqliteDistributedOperationStore:
        return SqliteDistributedOperationStore(path, self.catalog)

    def publish(
        self, store: SqliteDistributedOperationStore, operation_id: str = "operation_alpha_001", *,
        tenant_id: str = "tenant_alpha", max_attempts: int = 3,
    ) -> dict:
        return store.execute_operation(
            tenant_id, operation_id, {"status": "committed"},
            [{"topic": "evolution_events", "payload": {"event": operation_id}}],
            max_attempts=max_attempts, now=self.now,
        )

    @conformance("D-ADP-001")
    def test_adapter_contract_and_capabilities_do_not_overclaim_multihost(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            store = self.store(Path(directory_name) / "distributed.db")
            self.assertIsInstance(store, DistributedOperationStoreAdapter)
            capabilities = store.capabilities()
            self.assertTrue(capabilities["transactional_outbox"])
            self.assertTrue(capabilities["runtime_verified"])
            self.assertTrue(capabilities["multi_process"])
            self.assertFalse(capabilities["skip_locked_claim"])
            self.assertFalse(capabilities["multi_host"])

    @conformance("D-TXO-001")
    def test_operation_and_outbox_commit_atomically_and_replay_original_messages(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            store = self.store(Path(directory_name) / "distributed.db")
            first = self.publish(store)
            replay = self.publish(store)
            self.assertFalse(first["idempotent_replay"])
            self.assertTrue(replay["idempotent_replay"])
            self.assertEqual(
                [item["message_id"] for item in first["messages"]],
                [item["message_id"] for item in replay["messages"]],
            )
            with self.assertRaises(ANOError) as conflict:
                store.execute_operation(
                    "tenant_alpha", "operation_alpha_001", {"status": "changed"},
                    [{"topic": "evolution_events", "payload": {"event": "different"}}],
                )
            self.assertEqual("OUTBOX_IDEMPOTENCY_CONFLICT", conflict.exception.code)

    @conformance("D-INB-001")
    def test_inbox_and_effect_are_exactly_once_for_database_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            store = self.store(Path(directory_name) / "distributed.db")
            message = self.publish(store)["messages"][0]
            lease = store.acquire_lease("queue_evolution", "node_alpha", now=self.now)
            claimed = store.claim_next(
                lease, ["evolution_events"], ["tenant_alpha"], now=self.now,
            )
            self.assertEqual(message["message_id"], claimed["message_id"])
            effect = {"projection": "applied", "version": 1}
            receipt = store.complete(
                lease, claimed["message_id"], "consumer_projection", effect, now=self.now,
            )
            replay = store.complete(
                lease, claimed["message_id"], "consumer_projection", effect,
                now=self.now + timedelta(hours=1),
            )
            self.assertFalse(receipt["idempotent_replay"])
            self.assertTrue(replay["idempotent_replay"])
            self.assertEqual(receipt["receipt_id"], replay["receipt_id"])
            self.assertEqual(effect, store.effect("consumer_projection", claimed["message_id"]))
            with self.assertRaises(ANOError) as conflict:
                store.complete(
                    lease, claimed["message_id"], "consumer_projection", {"projection": "different"},
                    now=self.now + timedelta(hours=1),
                )
            self.assertEqual("INBOX_IDEMPOTENCY_CONFLICT", conflict.exception.code)

    @conformance("D-TEN-001")
    def test_claim_requires_explicit_tenant_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            store = self.store(Path(directory_name) / "distributed.db")
            alpha = self.publish(store, "operation_alpha_scope", tenant_id="tenant_alpha")["messages"][0]
            beta = self.publish(store, "operation_beta_scope", tenant_id="tenant_beta")["messages"][0]
            lease = store.acquire_lease("queue_evolution", "node_alpha", now=self.now)
            claimed = store.claim_next(
                lease, ["evolution_events"], ["tenant_beta"], now=self.now,
            )
            self.assertEqual(beta["message_id"], claimed["message_id"])
            self.assertEqual("pending", store.message(alpha["message_id"])["status"])
            with self.assertRaises(ANOError) as missing_scope:
                store.claim_next(lease, ["evolution_events"], [], now=self.now)
            self.assertEqual("OUTBOX_CLAIM_INVALID", missing_scope.exception.code)

    @conformance("D-FEN-001")
    def test_new_epoch_fences_partitioned_worker_and_reclaims_expired_message(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            store = self.store(Path(directory_name) / "distributed.db")
            self.publish(store)
            first = store.acquire_lease(
                "queue_evolution", "node_alpha", ttl_seconds=5, now=self.now,
            )
            message = store.claim_next(
                first, ["evolution_events"], ["tenant_alpha"], claim_ttl_seconds=5, now=self.now,
            )
            second = store.acquire_lease(
                "queue_evolution", "node_beta", ttl_seconds=10, now=self.now + timedelta(seconds=6),
            )
            self.assertEqual(first["epoch"] + 1, second["epoch"])
            with self.assertRaises(ANOError) as fenced:
                store.complete(
                    first, message["message_id"], "consumer_projection", {"stale": True},
                    now=self.now + timedelta(seconds=6),
                )
            self.assertEqual("DISTRIBUTED_FENCE_REJECTED", fenced.exception.code)
            reclaimed = store.claim_next(
                second, ["evolution_events"], ["tenant_alpha"], now=self.now + timedelta(seconds=6),
            )
            self.assertEqual(message["message_id"], reclaimed["message_id"])
            self.assertEqual(2, reclaimed["attempts"])

    @conformance("D-REC-001")
    def test_restart_requeues_expired_claim_without_losing_message(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "distributed.db"
            first = self.store(path)
            message = self.publish(first)["messages"][0]
            lease = first.acquire_lease("queue_evolution", "node_alpha", now=self.now)
            first.claim_next(
                lease, ["evolution_events"], ["tenant_alpha"], claim_ttl_seconds=2, now=self.now,
            )
            restarted = self.store(path)
            report = restarted.recover(now=self.now + timedelta(seconds=3))
            self.assertEqual(1, report["requeued"])
            self.assertEqual("pending", restarted.message(message["message_id"])["status"])

    @conformance("D-DLQ-001")
    def test_poison_message_moves_to_dead_letter_after_bounded_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            store = self.store(Path(directory_name) / "distributed.db")
            message = self.publish(store, max_attempts=2)["messages"][0]
            lease = store.acquire_lease("queue_evolution", "node_alpha", now=self.now)
            first = store.claim_next(
                lease, ["evolution_events"], ["tenant_alpha"], now=self.now,
            )
            self.assertEqual("pending", store.fail(
                lease, first["message_id"], "transient", now=self.now,
            ))
            second = store.claim_next(
                lease, ["evolution_events"], ["tenant_alpha"], now=self.now + timedelta(seconds=1),
            )
            self.assertEqual("dead_letter", store.fail(
                lease, second["message_id"], "poison", now=self.now + timedelta(seconds=1),
            ))
            self.assertEqual("dead_letter", store.message(message["message_id"])["status"])
            self.assertIsNone(store.claim_next(
                lease, ["evolution_events"], ["tenant_alpha"], now=self.now + timedelta(seconds=2),
            ))

    @conformance("D-CON-001")
    def test_concurrent_claimers_observe_at_most_one_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "distributed.db"
            first = self.store(path)
            second = self.store(path)
            message = self.publish(first)["messages"][0]
            lease = first.acquire_lease("queue_evolution", "node_alpha", now=self.now)

            def claim(store: SqliteDistributedOperationStore) -> dict | None:
                return store.claim_next(
                    lease, ["evolution_events"], ["tenant_alpha"], now=self.now,
                )

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(claim, (first, second)))
            claimed = [item for item in results if item is not None]
            self.assertEqual(1, len(claimed))
            self.assertEqual(message["message_id"], claimed[0]["message_id"])

    @conformance("D-PGC-001")
    def test_postgres_plan_uses_skip_locked_and_remains_explicitly_unverified(self) -> None:
        ddl = PostgresDistributedAdapterPlan.ddl()
        capabilities = PostgresDistributedAdapterPlan.capabilities(self.catalog)
        self.assertTrue(any("JSONB" in statement for statement in ddl))
        self.assertIn("FOR UPDATE SKIP LOCKED", PostgresDistributedAdapterPlan.CLAIM_SQL)
        self.assertTrue(capabilities["skip_locked_claim"])
        self.assertFalse(capabilities["runtime_verified"])
        self.assertFalse(capabilities["multi_host"])

    @conformance("D-E2E-001")
    def test_one_command_distributed_demo_emits_machine_valid_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            output = Path(directory_name) / "distributed-acceptance.json"
            completed = subprocess.run(
                [sys.executable, str(STANDARD_ROOT / "tools" / "run_v050_distributed_demo.py"), "--output", str(output)],
                cwd=STANDARD_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.catalog.validate("distributed-acceptance-report", report)
            self.assertEqual("passed", report["status"])
            self.assertEqual(11, len(report["checks"]))
            self.assertFalse(report["postgres_runtime_verified"])


if __name__ == "__main__":
    unittest.main()
