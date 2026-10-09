from __future__ import annotations

import base64
import copy
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ANOError
from .schema import SchemaCatalog
from .util import canonical_json, new_id, sha256_json, utc_now


class InMemoryKmsProvider:
    """Reference KMS contract: non-exporting versioned master keys with authenticated wrapping."""

    def __init__(self, provider_id: str = "kms_reference", master_key_id: str = "master_ano") -> None:
        self.provider_id = provider_id
        self.master_key_id = master_key_id
        self._keys: dict[int, bytes] = {1: AESGCM.generate_key(bit_length=256)}
        self._status: dict[int, str] = {1: "active"}
        self._active_version = 1

    @property
    def active_version(self) -> int:
        return self._active_version

    def rotate(self) -> int:
        self._status[self._active_version] = "retired"
        version = max(self._keys) + 1
        self._keys[version] = AESGCM.generate_key(bit_length=256)
        self._status[version] = "active"
        self._active_version = version
        return version

    def destroy(self, version: int) -> None:
        if version == self._active_version:
            raise ANOError("KMS_ACTIVE_KEY_DESTROY", "active KMS master key cannot be destroyed before rotation")
        if version not in self._status:
            raise ANOError("KMS_KEY_UNKNOWN", "KMS master key version is unknown")
        self._status[version] = "destroyed"
        self._keys.pop(version, None)

    def wrap_key(self, plaintext_key: bytes, context: dict[str, Any]) -> dict[str, Any]:
        if len(plaintext_key) != 32:
            raise ANOError("KMS_PLAINTEXT_KEY_INVALID", "only 256-bit data keys may be wrapped")
        version = self._active_version
        nonce = os.urandom(12)
        aad = canonical_json(context).encode("utf-8")
        ciphertext = AESGCM(self._keys[version]).encrypt(nonce, plaintext_key, aad)
        return {
            "provider_id": self.provider_id, "master_key_id": self.master_key_id,
            "master_key_version": version, "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "context_hash": sha256_json(context),
        }

    def unwrap_key(self, envelope: dict[str, Any], context: dict[str, Any]) -> bytes:
        if envelope.get("provider_id") != self.provider_id or envelope.get("master_key_id") != self.master_key_id:
            raise ANOError("KMS_KEY_IDENTITY_MISMATCH", "wrapped key belongs to a different KMS identity")
        if envelope.get("context_hash") != sha256_json(context):
            raise ANOError("KMS_CONTEXT_MISMATCH", "wrapped key context differs from its authenticated binding")
        version = int(envelope["master_key_version"])
        key = self._keys.get(version)
        if key is None or self._status.get(version) == "destroyed":
            raise ANOError("KMS_KEY_DESTROYED", "KMS master key material is unavailable")
        try:
            nonce = base64.b64decode(envelope["nonce"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            return AESGCM(key).decrypt(nonce, ciphertext, canonical_json(context).encode("utf-8"))
        except (ValueError, InvalidTag) as exc:
            raise ANOError("KMS_UNWRAP_FAILED", "wrapped data key integrity verification failed") from exc


class SqliteTenantKeyManager:
    """Persist only KMS-wrapped tenant data keys; plaintext DEKs exist only during crypto operations."""

    def __init__(self, path: str | Path, catalog: SchemaCatalog, provider: InMemoryKmsProvider) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.provider = provider
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, isolation_level=None)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenant_data_keys (
                    tenant_id TEXT NOT NULL,
                    key_version INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('active', 'retired', 'destroyed')),
                    wrapped_key_json TEXT,
                    created_at TEXT NOT NULL,
                    retired_at TEXT,
                    destroyed_at TEXT,
                    PRIMARY KEY (tenant_id, key_version)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_active_data_key
                    ON tenant_data_keys (tenant_id) WHERE status = 'active';
                """
            )
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _context(tenant_id: str, key_version: int) -> dict[str, Any]:
        return {"purpose": "ano-tenant-data-key", "tenant_id": tenant_id, "key_version": key_version}

    def _active_row(self, connection: sqlite3.Connection, tenant_id: str) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM tenant_data_keys WHERE tenant_id = ? AND status = 'active'", (tenant_id,),
        ).fetchone()

    def _ensure_active(self, connection: sqlite3.Connection, tenant_id: str) -> sqlite3.Row:
        row = self._active_row(connection, tenant_id)
        if row is not None:
            return row
        maximum = connection.execute(
            "SELECT MAX(key_version) AS maximum FROM tenant_data_keys WHERE tenant_id = ?", (tenant_id,),
        ).fetchone()
        key_version = 1 if maximum is None or maximum["maximum"] is None else int(maximum["maximum"]) + 1
        data_key = AESGCM.generate_key(bit_length=256)
        wrapped = self.provider.wrap_key(data_key, self._context(tenant_id, key_version))
        self.catalog.validate("kms-wrapped-key", wrapped)
        connection.execute(
            """INSERT INTO tenant_data_keys
               (tenant_id, key_version, status, wrapped_key_json, created_at, retired_at, destroyed_at)
               VALUES (?, ?, 'active', ?, ?, NULL, NULL)""",
            (tenant_id, key_version, canonical_json(wrapped), utc_now()),
        )
        row = self._active_row(connection, tenant_id)
        assert row is not None
        return row

    def _unwrap_row(self, row: sqlite3.Row, tenant_id: str) -> bytes:
        if row["status"] == "destroyed" or row["wrapped_key_json"] is None:
            raise ANOError("TENANT_KEY_DESTROYED", "tenant data key has been cryptographically destroyed")
        try:
            wrapped = json.loads(row["wrapped_key_json"])
            self.catalog.validate("kms-wrapped-key", wrapped)
        except (json.JSONDecodeError, ANOError) as exc:
            raise ANOError("TENANT_KEY_CORRUPT", "wrapped tenant data key record is corrupt") from exc
        return self.provider.unwrap_key(wrapped, self._context(tenant_id, int(row["key_version"])))

    def encrypt_json(
        self, tenant_id: str, namespace: str, object_id: str, object_version: int,
        payload: dict[str, Any], *, connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        owned = connection is None
        active_connection = connection or self._connect()
        try:
            row = self._ensure_active(active_connection, tenant_id)
            data_key = self._unwrap_row(row, tenant_id)
            aad_material = {
                "tenant_id": tenant_id, "namespace": namespace, "object_id": object_id,
                "object_version": object_version, "key_version": int(row["key_version"]),
            }
            nonce = os.urandom(12)
            plaintext = canonical_json(payload).encode("utf-8")
            ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, canonical_json(aad_material).encode("utf-8"))
            envelope = {
                "schema_version": "0.4.0", "tenant_id": tenant_id,
                "key_version": int(row["key_version"]), "algorithm": "AES-256-GCM",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "plaintext_hash": sha256_json(payload), "aad_hash": sha256_json(aad_material),
                "encrypted_at": utc_now(),
            }
            self.catalog.validate("encrypted-payload-envelope", envelope)
            return envelope
        finally:
            if owned:
                active_connection.close()

    def decrypt_json(
        self, tenant_id: str, namespace: str, object_id: str, object_version: int,
        envelope: dict[str, Any], *, connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        self.catalog.validate("encrypted-payload-envelope", envelope)
        if envelope["tenant_id"] != tenant_id:
            raise ANOError("TENANT_CIPHERTEXT_SCOPE_MISMATCH", "ciphertext is bound to another tenant")
        key_version = int(envelope["key_version"])
        aad_material = {
            "tenant_id": tenant_id, "namespace": namespace, "object_id": object_id,
            "object_version": object_version, "key_version": key_version,
        }
        if envelope["aad_hash"] != sha256_json(aad_material):
            raise ANOError("TENANT_CIPHERTEXT_SCOPE_MISMATCH", "ciphertext object scope was modified")
        owned = connection is None
        active_connection = connection or self._connect()
        try:
            row = active_connection.execute(
                "SELECT * FROM tenant_data_keys WHERE tenant_id = ? AND key_version = ?",
                (tenant_id, key_version),
            ).fetchone()
            if row is None:
                raise ANOError("TENANT_KEY_MISSING", "ciphertext references an unavailable tenant data key")
            data_key = self._unwrap_row(row, tenant_id)
            try:
                plaintext = AESGCM(data_key).decrypt(
                    base64.b64decode(envelope["nonce"], validate=True),
                    base64.b64decode(envelope["ciphertext"], validate=True),
                    canonical_json(aad_material).encode("utf-8"),
                )
                payload = json.loads(plaintext.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError, InvalidTag) as exc:
                raise ANOError("TENANT_DECRYPT_FAILED", "tenant ciphertext integrity verification failed") from exc
            if not isinstance(payload, dict) or sha256_json(payload) != envelope["plaintext_hash"]:
                raise ANOError("TENANT_DECRYPT_FAILED", "tenant plaintext hash verification failed")
            return payload
        finally:
            if owned:
                active_connection.close()

    def rotate_tenant_key(self, tenant_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._ensure_active(connection, tenant_id)
            old_version = int(current["key_version"])
            rotated_at = utc_now()
            connection.execute(
                "UPDATE tenant_data_keys SET status = 'retired', retired_at = ? WHERE tenant_id = ? AND key_version = ?",
                (rotated_at, tenant_id, old_version),
            )
            new_row = self._ensure_active(connection, tenant_id)
            receipt = {
                "rotation_id": new_id("tkr"), "schema_version": "0.4.0", "tenant_id": tenant_id,
                "old_key_version": old_version, "new_key_version": int(new_row["key_version"]),
                "rotated_at": rotated_at, "kms_master_key_version": self.provider.active_version,
            }
            self.catalog.validate("tenant-key-rotation-receipt", receipt)
            connection.commit()
            return receipt
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def rewrap_for_active_master_key(self, tenant_id: str) -> int:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM tenant_data_keys WHERE tenant_id = ? AND status != 'destroyed' ORDER BY key_version",
                (tenant_id,),
            ).fetchall()
            count = 0
            for row in rows:
                key_version = int(row["key_version"])
                data_key = self._unwrap_row(row, tenant_id)
                wrapped = self.provider.wrap_key(data_key, self._context(tenant_id, key_version))
                self.catalog.validate("kms-wrapped-key", wrapped)
                connection.execute(
                    "UPDATE tenant_data_keys SET wrapped_key_json = ? WHERE tenant_id = ? AND key_version = ?",
                    (canonical_json(wrapped), tenant_id, key_version),
                )
                count += 1
            connection.commit()
            return count
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def crypto_shred(self, tenant_id: str, reason: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT key_version FROM tenant_data_keys WHERE tenant_id = ? AND status != 'destroyed' ORDER BY key_version",
                (tenant_id,),
            ).fetchall()
            versions = [int(row["key_version"]) for row in rows]
            if not versions:
                raise ANOError("TENANT_KEY_MISSING", "tenant has no destroyable data keys")
            destroyed_at = utc_now()
            connection.execute(
                """UPDATE tenant_data_keys SET status = 'destroyed', wrapped_key_json = NULL,
                   destroyed_at = ? WHERE tenant_id = ? AND status != 'destroyed'""",
                (destroyed_at, tenant_id),
            )
            receipt = {
                "destruction_id": new_id("tkd"), "schema_version": "0.4.0", "tenant_id": tenant_id,
                "destroyed_key_versions": versions, "reason": reason, "destroyed_at": destroyed_at,
                "recoverable": False,
            }
            self.catalog.validate("tenant-key-destruction-receipt", receipt)
            connection.commit()
            return receipt
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def key_metadata(self, tenant_id: str) -> tuple[dict[str, Any], ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT tenant_id, key_version, status, created_at, retired_at, destroyed_at
                   FROM tenant_data_keys WHERE tenant_id = ? ORDER BY key_version""",
                (tenant_id,),
            ).fetchall()
            return tuple(dict(row) for row in rows)
        finally:
            connection.close()
