from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ano_runtime import (
    ANOError,
    InMemoryKmsProvider,
    SchemaCatalog,
    SqliteTenantKeyManager,
    SqliteTenantStateStore,
    TenantAccessBoundary,
)

from tests.support import STANDARD_ROOT, conformance


class TenantKeyManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.4.0")
        self.boundary = TenantAccessBoundary(
            self.catalog,
            {"principal_alpha": "tenant_alpha", "principal_beta": "tenant_beta"},
            secret=b"alpha2-encryption-boundary-secret-32-bytes-minimum",
        )

    def _encrypted_store(
        self, path: Path,
    ) -> tuple[InMemoryKmsProvider, SqliteTenantKeyManager, SqliteTenantStateStore]:
        provider = InMemoryKmsProvider()
        manager = SqliteTenantKeyManager(path, self.catalog, provider)
        store = SqliteTenantStateStore(path, self.catalog, self.boundary, key_manager=manager)
        return provider, manager, store

    @conformance("O-ENC-001")
    def test_payload_is_ciphertext_at_rest_and_authenticated_on_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "encrypted.db"
            _, _, store = self._encrypted_store(path)
            session = self.boundary.open_session("principal_alpha")
            secret = "credential-value-that-must-never-appear-at-rest"
            store.put(
                session, "credentials", "credential_alpha", {"secret": secret, "enabled": True},
                expected_version=0, idempotency_key="idem_encrypt_alpha",
            )

            connection = sqlite3.connect(path)
            try:
                stored = connection.execute(
                    "SELECT payload_json, payload_encoding FROM tenant_objects WHERE tenant_id = ?",
                    ("tenant_alpha",),
                ).fetchone()
            finally:
                connection.close()
            assert stored is not None
            self.assertEqual("aes-256-gcm-envelope-v1", stored[1])
            self.assertNotIn(secret, stored[0])
            self.catalog.validate("encrypted-payload-envelope", json.loads(stored[0]))

            result = store.get(session, "credentials", "credential_alpha")
            self.assertEqual(secret, result["payload"]["secret"])
            self.assertEqual("AES-256-GCM", result["encryption"]["algorithm"])
            self.assertEqual(1, result["encryption"]["key_version"])

            envelope = json.loads(stored[0])
            replacement = "A" if envelope["ciphertext"][0] != "A" else "B"
            envelope["ciphertext"] = replacement + envelope["ciphertext"][1:]
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE tenant_objects SET payload_json = ? WHERE tenant_id = ?",
                    (json.dumps(envelope), "tenant_alpha"),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ANOError) as tampered:
                store.get(session, "credentials", "credential_alpha")
            self.assertEqual("TENANT_DECRYPT_FAILED", tampered.exception.code)

    @conformance("O-ENC-002")
    def test_ciphertext_cannot_be_substituted_between_object_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "encrypted.db"
            _, _, store = self._encrypted_store(path)
            session = self.boundary.open_session("principal_alpha")
            store.put(
                session, "memory", "object_alpha_001", {"value": "first"},
                expected_version=0, idempotency_key="idem_scope_first",
            )
            store.put(
                session, "memory", "object_alpha_002", {"value": "second"},
                expected_version=0, idempotency_key="idem_scope_second",
            )
            connection = sqlite3.connect(path)
            try:
                first = connection.execute(
                    "SELECT payload_json FROM tenant_objects WHERE tenant_id = ? AND object_id = ?",
                    ("tenant_alpha", "object_alpha_001"),
                ).fetchone()
                assert first is not None
                connection.execute(
                    "UPDATE tenant_objects SET payload_json = ? WHERE tenant_id = ? AND object_id = ?",
                    (first[0], "tenant_alpha", "object_alpha_002"),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ANOError) as substituted:
                store.get(session, "memory", "object_alpha_002")
            self.assertEqual("TENANT_CIPHERTEXT_SCOPE_MISMATCH", substituted.exception.code)

    @conformance("O-KEY-001")
    def test_data_and_master_key_rotation_preserve_decryption(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "encrypted.db"
            provider, manager, store = self._encrypted_store(path)
            session = self.boundary.open_session("principal_alpha")
            store.put(
                session, "memory", "object_before", {"generation": 1},
                expected_version=0, idempotency_key="idem_before_rotation",
            )
            receipt = manager.rotate_tenant_key("tenant_alpha")
            self.assertEqual((1, 2), (receipt["old_key_version"], receipt["new_key_version"]))
            store.put(
                session, "memory", "object_after", {"generation": 2},
                expected_version=0, idempotency_key="idem_after_rotation",
            )
            self.assertEqual(1, store.get(session, "memory", "object_before")["encryption"]["key_version"])
            self.assertEqual(2, store.get(session, "memory", "object_after")["encryption"]["key_version"])

            old_master_version = provider.active_version
            self.assertEqual(2, provider.rotate())
            self.assertEqual(2, manager.rewrap_for_active_master_key("tenant_alpha"))
            provider.destroy(old_master_version)
            self.assertEqual(1, store.get(session, "memory", "object_before")["payload"]["generation"])
            self.assertEqual(2, store.get(session, "memory", "object_after")["payload"]["generation"])

    @conformance("O-KEY-002")
    def test_crypto_shredding_is_tenant_scoped_and_irreversible(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "encrypted.db"
            _, manager, store = self._encrypted_store(path)
            alpha = self.boundary.open_session("principal_alpha")
            beta = self.boundary.open_session("principal_beta")
            store.put(
                alpha, "memory", "object_shared", {"owner": "alpha"},
                expected_version=0, idempotency_key="idem_shred_alpha",
            )
            manager.rotate_tenant_key("tenant_alpha")
            store.put(
                alpha, "memory", "object_second", {"owner": "alpha-second"},
                expected_version=0, idempotency_key="idem_shred_alpha_second",
            )
            store.put(
                beta, "memory", "object_shared", {"owner": "beta"},
                expected_version=0, idempotency_key="idem_shred_beta",
            )

            receipt = manager.crypto_shred("tenant_alpha", "verified tenant erasure request")
            self.assertEqual([1, 2], receipt["destroyed_key_versions"])
            self.assertFalse(receipt["recoverable"])
            self.assertTrue(all(item["status"] == "destroyed" for item in manager.key_metadata("tenant_alpha")))
            with self.assertRaises(ANOError) as shredded:
                store.get(alpha, "memory", "object_shared")
            self.assertEqual("TENANT_KEY_DESTROYED", shredded.exception.code)
            self.assertEqual("beta", store.get(beta, "memory", "object_shared")["payload"]["owner"])

    @conformance("O-KEY-003")
    def test_encrypted_store_requires_the_matching_key_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            first = Path(directory_name) / "first.db"
            second = Path(directory_name) / "second.db"
            provider = InMemoryKmsProvider()
            manager = SqliteTenantKeyManager(first, self.catalog, provider)
            with self.assertRaises(ANOError) as mismatch:
                SqliteTenantStateStore(second, self.catalog, self.boundary, key_manager=manager)
            self.assertEqual("TENANT_KEY_STORE_MISMATCH", mismatch.exception.code)


if __name__ == "__main__":
    unittest.main()
