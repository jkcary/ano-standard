from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from ano_runtime import (
    ANOError,
    InMemoryKmsProvider,
    SchemaCatalog,
    SqliteBackupManager,
    SqliteTenantKeyManager,
    SqliteTenantMigrationManager,
    SqliteTenantStateStore,
    TenantStateStoreAdapter,
    TenantAccessBoundary,
)

from tests.support import STANDARD_ROOT, conformance


class TenantMigrationAndBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.4.0")
        self.boundary = TenantAccessBoundary(
            self.catalog,
            {"principal_alpha": "tenant_alpha", "principal_beta": "tenant_beta"},
            secret=b"alpha3-migration-boundary-secret-32-bytes-minimum",
        )

    def _store(
        self, path: Path, provider: InMemoryKmsProvider | None = None,
    ) -> tuple[InMemoryKmsProvider, SqliteTenantStateStore]:
        active_provider = provider or InMemoryKmsProvider()
        manager = SqliteTenantKeyManager(path, self.catalog, active_provider)
        return active_provider, SqliteTenantStateStore(
            path, self.catalog, self.boundary, key_manager=manager,
        )

    @conformance("O-MIG-001")
    def test_encrypted_export_import_preserves_state_history_and_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            _, source = self._store(directory / "source.db")
            _, target = self._store(directory / "target.db")
            session = self.boundary.open_session("principal_alpha")
            first = source.put(
                session, "goals", "goal_alpha", {"status": "active", "secret": "source-only"},
                expected_version=0, idempotency_key="idem_migration_create",
            )
            source.put(
                session, "memory", "memory_alpha", {"fact": "portable"},
                expected_version=0, idempotency_key="idem_migration_memory",
            )
            source.delete(
                session, "memory", "memory_alpha", expected_version=1,
                idempotency_key="idem_migration_delete",
            )
            transfer_key = b"m" * 32
            envelope = SqliteTenantMigrationManager(source).transfer.encrypt_export(session, transfer_key)
            self.assertNotIn("source-only", envelope["ciphertext"])

            receipt = SqliteTenantMigrationManager(target).import_encrypted(session, envelope, transfer_key)
            self.assertTrue(receipt["atomic"])
            self.assertEqual((2, 3, 3), (
                receipt["object_count"], receipt["event_count"], receipt["idempotency_count"],
            ))
            self.assertEqual(source.head_hash(session), target.head_hash(session))
            self.assertEqual("source-only", target.get(session, "goals", "goal_alpha")["payload"]["secret"])
            self.assertEqual("deleted", target.get(
                session, "memory", "memory_alpha", include_deleted=True,
            )["status"])
            target.verify_tenant_log(session, expected_head_hash=source.head_hash(session))

            replay = target.put(
                session, "goals", "goal_alpha", {"status": "active", "secret": "source-only"},
                expected_version=0, idempotency_key="idem_migration_create",
            )
            self.assertTrue(replay["idempotent_replay"])
            self.assertEqual(first["transaction_id"], replay["transaction_id"])

    @conformance("O-ADP-001")
    def test_sqlite_implements_portable_adapter_contract_without_multinode_overclaim(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            _, store = self._store(Path(directory_name) / "adapter.db")
            self.assertIsInstance(store, TenantStateStoreAdapter)
            capabilities = store.capabilities()
            self.assertTrue(capabilities["atomic_tenant_writes"])
            self.assertTrue(capabilities["tenant_envelope_encryption"])
            self.assertTrue(capabilities["portable_migration"])
            self.assertFalse(capabilities["multi_node"])

    @conformance("O-MIG-002")
    def test_import_rejects_wrong_key_tamper_scope_and_nonempty_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            _, source = self._store(directory / "source.db")
            _, target = self._store(directory / "target.db")
            alpha = self.boundary.open_session("principal_alpha")
            beta = self.boundary.open_session("principal_beta")
            source.put(
                alpha, "memory", "object_alpha", {"value": 1},
                expected_version=0, idempotency_key="idem_migration_alpha",
            )
            transfer_key = b"t" * 32
            envelope = SqliteTenantMigrationManager(source).transfer.encrypt_export(alpha, transfer_key)
            migration = SqliteTenantMigrationManager(target)
            with self.assertRaises(ANOError) as wrong_key:
                migration.import_encrypted(alpha, envelope, b"w" * 32)
            self.assertEqual("TENANT_TRANSFER_DECRYPT_FAILED", wrong_key.exception.code)
            with self.assertRaises(ANOError) as scope:
                migration.import_encrypted(beta, envelope, transfer_key)
            self.assertEqual("TENANT_MIGRATION_SCOPE_MISMATCH", scope.exception.code)
            tampered = copy.deepcopy(envelope)
            tampered["package_hash"] = "sha256:" + "0" * 64
            with self.assertRaises(ANOError) as changed:
                migration.import_encrypted(alpha, tampered, transfer_key)
            self.assertEqual("TENANT_TRANSFER_BINDING_INVALID", changed.exception.code)

            target.put(
                alpha, "memory", "existing_alpha", {"value": "occupied"},
                expected_version=0, idempotency_key="idem_existing_alpha",
            )
            with self.assertRaises(ANOError) as occupied:
                migration.import_encrypted(alpha, envelope, transfer_key)
            self.assertEqual("TENANT_MIGRATION_TARGET_NOT_EMPTY", occupied.exception.code)
            self.assertEqual(1, len(target.audit_events(alpha)))

    @conformance("O-BAK-001")
    def test_online_backup_restores_encrypted_database_and_rejects_changed_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            provider, source = self._store(directory / "source.db")
            session = self.boundary.open_session("principal_alpha")
            source.put(
                session, "memory", "object_backup", {"value": "recoverable"},
                expected_version=0, idempotency_key="idem_backup_alpha",
            )
            backup = directory / "source.backup.db"
            manager = SqliteBackupManager(source)
            manifest = manager.create(backup)
            restored_path = directory / "restored.db"
            manager.restore(backup, manifest, restored_path)
            restored_manager = SqliteTenantKeyManager(restored_path, self.catalog, provider)
            restored = SqliteTenantStateStore(
                restored_path, self.catalog, self.boundary, key_manager=restored_manager,
            )
            self.assertEqual("recoverable", restored.get(
                session, "memory", "object_backup",
            )["payload"]["value"])
            restored.verify_tenant_log(session, expected_head_hash=source.head_hash(session))

            changed_backup = directory / "changed.backup.db"
            changed_backup.write_bytes(backup.read_bytes() + b"changed")
            with self.assertRaises(ANOError) as changed:
                manager.restore(changed_backup, manifest, directory / "rejected.db")
            self.assertEqual("BACKUP_CONTENT_MISMATCH", changed.exception.code)
            self.assertFalse((directory / "rejected.db").exists())


if __name__ == "__main__":
    unittest.main()
