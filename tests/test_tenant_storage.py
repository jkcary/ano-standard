from __future__ import annotations

import dataclasses
import sqlite3
import tempfile
import threading
import unittest
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ano_runtime import (
    ANOError, SchemaCatalog, SqliteTenantStateStore, TenantAccessBoundary, sha256_json,
)

from tests.support import STANDARD_ROOT, conformance


class TransactionalTenantStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.4.0")
        self.boundary = TenantAccessBoundary(
            self.catalog,
            {"principal_alpha": "tenant_alpha", "principal_beta": "tenant_beta"},
            secret=b"alpha1-reference-boundary-secret-32-bytes-minimum",
        )

    @conformance("O-SCH-001")
    def test_v040_schema_catalog_is_complete_and_valid(self) -> None:
        self.catalog.check_all()
        directory = STANDARD_ROOT / "schemas" / "v0.4.0"
        catalog = json.loads((directory / "catalog.json").read_text(encoding="utf-8"))
        declared = sorted(catalog["schemas"])
        present = sorted(path.name for path in directory.glob("*.schema.json"))
        self.assertEqual(present, declared)
        self.assertEqual(set(path.name.removesuffix(".schema.json") for path in directory.glob("*.schema.json")), set(self.catalog.schemas))

    @conformance("O-TEN-001")
    def test_tenant_sessions_prevent_cross_tenant_reads_and_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            store = SqliteTenantStateStore(Path(directory_name) / "state.db", self.catalog, self.boundary)
            alpha = self.boundary.open_session("principal_alpha")
            beta = self.boundary.open_session("principal_beta")
            store.put(alpha, "memory", "object_shared", {"owner": "alpha"}, expected_version=0, idempotency_key="idem_alpha_001")
            store.put(beta, "memory", "object_shared", {"owner": "beta"}, expected_version=0, idempotency_key="idem_beta_001")
            self.assertEqual("alpha", store.get(alpha, "memory", "object_shared")["payload"]["owner"])
            self.assertEqual("beta", store.get(beta, "memory", "object_shared")["payload"]["owner"])
            self.assertEqual(1, len(store.list_objects(alpha, "memory")))
            forged = dataclasses.replace(alpha, tenant_id="tenant_beta")
            with self.assertRaises(ANOError) as invalid:
                store.get(forged, "memory", "object_shared")
            self.assertEqual("TENANT_SESSION_INVALID", invalid.exception.code)
            with self.assertRaises(ANOError) as denied:
                self.boundary.open_session("principal_unknown")
            self.assertEqual("TENANT_ACCESS_DENIED", denied.exception.code)

    @conformance("O-TXN-001")
    def test_optimistic_transactions_and_idempotency_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "state.db"
            first_store = SqliteTenantStateStore(path, self.catalog, self.boundary)
            second_store = SqliteTenantStateStore(path, self.catalog, self.boundary)
            session = self.boundary.open_session("principal_alpha")
            first = first_store.put(
                session, "goals", "goal_alpha_001", {"status": "active"},
                expected_version=0, idempotency_key="idem_goal_create",
            )
            replay = second_store.put(
                session, "goals", "goal_alpha_001", {"status": "active"},
                expected_version=0, idempotency_key="idem_goal_create",
            )
            self.assertTrue(replay["idempotent_replay"])
            self.assertEqual(first["transaction_id"], replay["transaction_id"])
            self.assertEqual(1, len(first_store.audit_events(session)))
            with self.assertRaises(ANOError) as reused:
                second_store.put(
                    session, "goals", "goal_alpha_001", {"status": "changed"},
                    expected_version=0, idempotency_key="idem_goal_create",
                )
            self.assertEqual("IDEMPOTENCY_CONFLICT", reused.exception.code)
            with self.assertRaises(ANOError) as stale:
                second_store.put(
                    session, "goals", "goal_alpha_001", {"status": "changed"},
                    expected_version=0, idempotency_key="idem_goal_stale",
                )
            self.assertEqual("STATE_CONFLICT", stale.exception.code)
            self.assertEqual(1, first_store.get(session, "goals", "goal_alpha_001")["version"])
            self.assertEqual(1, len(first_store.audit_events(session)))
            deleted = first_store.delete(
                session, "goals", "goal_alpha_001", expected_version=1, idempotency_key="idem_goal_delete",
            )
            self.assertEqual(2, deleted["version"])
            with self.assertRaises(ANOError) as missing:
                first_store.get(session, "goals", "goal_alpha_001")
            self.assertEqual("OBJECT_NOT_FOUND", missing.exception.code)
            tombstone = first_store.get(session, "goals", "goal_alpha_001", include_deleted=True)
            self.assertEqual("deleted", tombstone["status"])
            self.assertIsNone(tombstone["payload"])

    @conformance("O-PORT-001")
    def test_tenant_audit_chain_detects_tamper_and_export_is_self_verifying(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "state.db"
            store = SqliteTenantStateStore(path, self.catalog, self.boundary)
            session = self.boundary.open_session("principal_alpha")
            store.put(session, "skills", "skill_alpha_001", {"version": "1.0.0"}, expected_version=0, idempotency_key="idem_skill_001")
            store.put(session, "policies", "policy_alpha_001", {"threshold": 0.8}, expected_version=0, idempotency_key="idem_policy_001")
            anchored_head = store.head_hash(session)
            store.verify_tenant_log(session, expected_head_hash=anchored_head)
            package = store.export_tenant(session)
            self.catalog.validate("tenant-export-package", package)
            material = dict(package)
            material.pop("package_hash")
            self.assertEqual(package["package_hash"], sha256_json(material))
            self.assertEqual(2, len(package["objects"]))
            self.assertEqual(2, len(package["audit_events"]))
            self.assertEqual(2, len(package["idempotency_records"]))
            self.assertEqual(anchored_head, package["audit_head_hash"])

            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "DELETE FROM tenant_audit_events WHERE tenant_id = ? AND sequence = 2",
                    ("tenant_alpha",),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ANOError) as truncated:
                store.verify_tenant_log(session, expected_head_hash=anchored_head)
            self.assertEqual("TENANT_AUDIT_TRUNCATED", truncated.exception.code)

            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE tenant_audit_events SET payload_hash = ? WHERE tenant_id = ? AND sequence = 1",
                    ("sha256:" + "0" * 64, "tenant_alpha"),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ANOError) as corrupt:
                store.verify_tenant_log(session)
            self.assertEqual("TENANT_AUDIT_CORRUPT", corrupt.exception.code)

    @conformance("O-SES-001")
    def test_expired_session_is_rejected_before_storage_access(self) -> None:
        short_boundary = TenantAccessBoundary(
            self.catalog, {"principal_alpha": "tenant_alpha"},
            secret=b"alpha1-expiry-boundary-secret-32-bytes-minimum", session_lifetime_seconds=1,
        )
        expired = short_boundary.open_session(
            "principal_alpha", now=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        with tempfile.TemporaryDirectory() as directory_name:
            store = SqliteTenantStateStore(Path(directory_name) / "state.db", self.catalog, short_boundary)
            with self.assertRaises(ANOError) as raised:
                store.list_objects(expired, "memory")
            self.assertEqual("TENANT_SESSION_EXPIRED", raised.exception.code)

    @conformance("O-CON-001")
    def test_simultaneous_writers_commit_exactly_one_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "state.db"
            first = SqliteTenantStateStore(path, self.catalog, self.boundary)
            second = SqliteTenantStateStore(path, self.catalog, self.boundary)
            session = self.boundary.open_session("principal_alpha")
            barrier = threading.Barrier(2)

            def write(store: SqliteTenantStateStore, value: str, idempotency_key: str) -> str:
                barrier.wait(timeout=5)
                try:
                    store.put(
                        session, "memory", "memory_race_001", {"value": value},
                        expected_version=0, idempotency_key=idempotency_key,
                    )
                    return "committed"
                except ANOError as exc:
                    return exc.code

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = tuple(executor.map(
                    lambda item: write(*item),
                    ((first, "first", "idem_race_first"), (second, "second", "idem_race_second")),
                ))
            self.assertEqual(["STATE_CONFLICT", "committed"], sorted(results))
            self.assertEqual(1, len(first.audit_events(session)))
            self.assertEqual(1, first.get(session, "memory", "memory_race_001")["version"])

    @conformance("O-E2E-001")
    def test_storage_demo_emits_machine_valid_acceptance_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            output = Path(directory_name) / "storage-acceptance.json"
            completed = subprocess.run(
                [sys.executable, str(STANDARD_ROOT / "tools" / "run_v040_storage_demo.py"), "--output", str(output)],
                cwd=STANDARD_ROOT, capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.catalog.validate("storage-acceptance-report", report)
            self.assertEqual("passed", report["status"])
            self.assertTrue(all(item["status"] == "passed" for item in report["checks"]))

    @conformance("O-INT-001")
    def test_state_and_idempotency_rows_are_rebound_to_audit_events_on_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "state.db"
            store = SqliteTenantStateStore(path, self.catalog, self.boundary)
            session = self.boundary.open_session("principal_alpha")
            store.put(
                session, "memory", "memory_integrity_001", {"value": "original"},
                expected_version=0, idempotency_key="idem_integrity_001",
            )
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE tenant_objects SET payload_json = ? WHERE tenant_id = ? AND namespace = ? AND object_id = ?",
                    ('{"value":"tampered"}', "tenant_alpha", "memory", "memory_integrity_001"),
                )
                row = connection.execute(
                    "SELECT receipt_json FROM tenant_idempotency WHERE tenant_id = ? AND idempotency_key = ?",
                    ("tenant_alpha", "idem_integrity_001"),
                ).fetchone()
                receipt = json.loads(row[0])
                receipt["transaction_id"] = "txn_tampered_integrity"
                connection.execute(
                    "UPDATE tenant_idempotency SET receipt_json = ? WHERE tenant_id = ? AND idempotency_key = ?",
                    (json.dumps(receipt, sort_keys=True, separators=(",", ":")), "tenant_alpha", "idem_integrity_001"),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ANOError) as state_corrupt:
                store.get(session, "memory", "memory_integrity_001")
            self.assertEqual("TENANT_STATE_CORRUPT", state_corrupt.exception.code)
            with self.assertRaises(ANOError) as receipt_corrupt:
                store.put(
                    session, "memory", "memory_integrity_001", {"value": "original"},
                    expected_version=0, idempotency_key="idem_integrity_001",
                )
            self.assertEqual("TENANT_IDEMPOTENCY_CORRUPT", receipt_corrupt.exception.code)


if __name__ == "__main__":
    unittest.main()
