from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ANOError
from .tenant_storage import SqliteTenantStateStore, TenantSession
from .util import canonical_json, new_id, sha256_json, utc_now


class TenantTransferCipher:
    """Authenticated tenant export transport; the transfer key is supplied out of band."""

    def __init__(self, store: SqliteTenantStateStore) -> None:
        self.store = store

    @staticmethod
    def _key(transfer_key: bytes) -> bytes:
        if len(transfer_key) != 32:
            raise ANOError("TENANT_TRANSFER_KEY_INVALID", "tenant transfer key must be exactly 256 bits")
        return bytes(transfer_key)

    def encrypt_export(self, session: TenantSession, transfer_key: bytes) -> dict[str, Any]:
        package = self.store.export_tenant(session)
        transfer_id = new_id("ttr")
        created_at = utc_now()
        aad = {
            "transfer_id": transfer_id, "schema_version": "0.4.0",
            "tenant_id": package["tenant_id"], "created_at": created_at,
        }
        nonce = os.urandom(12)
        plaintext = canonical_json(package).encode("utf-8")
        ciphertext = AESGCM(self._key(transfer_key)).encrypt(nonce, plaintext, canonical_json(aad).encode("utf-8"))
        envelope = {
            **aad, "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "package_hash": package["package_hash"],
        }
        self.store.catalog.validate("tenant-transfer-envelope", envelope)
        return envelope

    def decrypt_export(self, envelope: dict[str, Any], transfer_key: bytes) -> dict[str, Any]:
        self.store.catalog.validate("tenant-transfer-envelope", envelope)
        aad = {
            "transfer_id": envelope["transfer_id"], "schema_version": envelope["schema_version"],
            "tenant_id": envelope["tenant_id"], "created_at": envelope["created_at"],
        }
        try:
            plaintext = AESGCM(self._key(transfer_key)).decrypt(
                base64.b64decode(envelope["nonce"], validate=True),
                base64.b64decode(envelope["ciphertext"], validate=True),
                canonical_json(aad).encode("utf-8"),
            )
            package = json.loads(plaintext.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, InvalidTag) as exc:
            raise ANOError("TENANT_TRANSFER_DECRYPT_FAILED", "tenant transfer envelope verification failed") from exc
        self.store.catalog.validate("tenant-export-package", package)
        if package["tenant_id"] != envelope["tenant_id"] or package["package_hash"] != envelope["package_hash"]:
            raise ANOError("TENANT_TRANSFER_BINDING_INVALID", "tenant transfer envelope binding is invalid")
        return package


class SqliteTenantMigrationManager:
    """Verify and atomically import portable tenant history into an empty tenant scope."""

    def __init__(self, store: SqliteTenantStateStore) -> None:
        self.store = store
        self.transfer = TenantTransferCipher(store)

    def verify_package(self, package: dict[str, Any]) -> None:
        try:
            self.store.catalog.validate("tenant-export-package", package)
            material = copy.deepcopy(package)
            package_hash = material.pop("package_hash")
            if package_hash != sha256_json(material):
                raise ValueError("package hash mismatch")
            events = package["audit_events"]
            previous_hash: str | None = None
            latest_by_object: dict[tuple[str, str], dict[str, Any]] = {}
            for sequence, event in enumerate(events, start=1):
                self.store.catalog.validate("tenant-audit-event", event)
                if event["tenant_id"] != package["tenant_id"]:
                    raise ValueError("event tenant mismatch")
                if event["sequence"] != sequence or event["previous_hash"] != previous_hash:
                    raise ValueError("audit chain discontinuity")
                if event["record_hash"] != self.store._event_hash(event):
                    raise ValueError("audit record hash mismatch")
                previous_hash = event["record_hash"]
                latest_by_object[(event["namespace"], event["object_id"])] = event
            if package["audit_head_hash"] != previous_hash:
                raise ValueError("audit head mismatch")
            if len(package["objects"]) != len(latest_by_object):
                raise ValueError("object set does not match audit history")
            for state in package["objects"]:
                self.store.catalog.validate("tenant-state-object", state)
                event = latest_by_object.get((state["namespace"], state["object_id"]))
                expected_type = "tenant.object.put" if state["status"] == "active" else "tenant.object.delete"
                if (
                    state["tenant_id"] != package["tenant_id"] or event is None
                    or state["version"] != event["object_version"]
                    or state["payload_hash"] != event["payload_hash"]
                    or state["updated_at"] != event["recorded_at"]
                    or event["event_type"] != expected_type
                    or state["payload_hash"] != sha256_json(state["payload"])
                ):
                    raise ValueError("state-to-audit binding mismatch")
            event_by_sequence = {event["sequence"]: event for event in events}
            seen_keys: set[str] = set()
            for record in package["idempotency_records"]:
                self.store.catalog.validate("tenant-idempotency-record", record)
                receipt = record["receipt"]
                event = event_by_sequence.get(receipt["event_sequence"])
                if (
                    record["tenant_id"] != package["tenant_id"]
                    or record["idempotency_key"] in seen_keys or event is None
                    or record["idempotency_key"] != receipt["idempotency_key"]
                    or record["request_hash"] != event["request_hash"]
                    or receipt["transaction_id"] != event["transaction_id"]
                    or receipt["event_record_hash"] != event["record_hash"]
                ):
                    raise ValueError("idempotency binding mismatch")
                seen_keys.add(record["idempotency_key"])
        except (ANOError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ANOError) and exc.code == "TENANT_MIGRATION_PACKAGE_INVALID":
                raise
            raise ANOError("TENANT_MIGRATION_PACKAGE_INVALID", "tenant migration package verification failed") from exc

    def import_encrypted(
        self, session: TenantSession, envelope: dict[str, Any], transfer_key: bytes,
    ) -> dict[str, Any]:
        tenant_id = self.store.access_boundary.verify(session)
        package = self.transfer.decrypt_export(envelope, transfer_key)
        self.verify_package(package)
        if package["tenant_id"] != tenant_id:
            raise ANOError("TENANT_MIGRATION_SCOPE_MISMATCH", "migration package belongs to another tenant")
        connection = self.store._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            occupied = sum(int(connection.execute(query, (tenant_id,)).fetchone()[0]) for query in (
                "SELECT COUNT(*) FROM tenant_objects WHERE tenant_id = ?",
                "SELECT COUNT(*) FROM tenant_audit_events WHERE tenant_id = ?",
                "SELECT COUNT(*) FROM tenant_idempotency WHERE tenant_id = ?",
            ))
            if occupied:
                raise ANOError("TENANT_MIGRATION_TARGET_NOT_EMPTY", "migration requires an empty tenant scope")
            for state in package["objects"]:
                payload = state["payload"]
                if payload is None:
                    payload_json = None
                    encoding = "tombstone"
                elif self.store.key_manager is None:
                    payload_json = canonical_json(payload)
                    encoding = "plaintext-json"
                else:
                    encrypted = self.store.key_manager.encrypt_json(
                        tenant_id, state["namespace"], state["object_id"], state["version"], payload,
                        connection=connection,
                    )
                    payload_json = canonical_json(encrypted)
                    encoding = "aes-256-gcm-envelope-v1"
                connection.execute(
                    """INSERT INTO tenant_objects
                       (tenant_id, namespace, object_id, version, status, payload_json, payload_encoding,
                        payload_hash, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        tenant_id, state["namespace"], state["object_id"], state["version"], state["status"],
                        payload_json, encoding, state["payload_hash"], state["updated_at"],
                    ),
                )
            for event in package["audit_events"]:
                connection.execute(
                    """INSERT INTO tenant_audit_events
                       (tenant_id, sequence, event_id, transaction_id, idempotency_key, request_hash,
                        event_type, namespace, object_id, object_version, payload_hash, previous_hash,
                        recorded_at, record_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        tenant_id, event["sequence"], event["event_id"], event["transaction_id"],
                        event["idempotency_key"], event["request_hash"], event["event_type"],
                        event["namespace"], event["object_id"], event["object_version"], event["payload_hash"],
                        event["previous_hash"], event["recorded_at"], event["record_hash"],
                    ),
                )
            for record in package["idempotency_records"]:
                connection.execute(
                    """INSERT INTO tenant_idempotency
                       (tenant_id, idempotency_key, request_hash, receipt_json) VALUES (?, ?, ?, ?)""",
                    (
                        tenant_id, record["idempotency_key"], record["request_hash"],
                        canonical_json(record["receipt"]),
                    ),
                )
            receipt = {
                "import_id": new_id("tim"), "schema_version": "0.4.0", "tenant_id": tenant_id,
                "source_package_hash": package["package_hash"], "source_audit_head_hash": package["audit_head_hash"],
                "object_count": len(package["objects"]), "event_count": len(package["audit_events"]),
                "idempotency_count": len(package["idempotency_records"]), "imported_at": utc_now(),
                "atomic": True,
            }
            self.store.catalog.validate("tenant-import-receipt", receipt)
            connection.commit()
            return receipt
        except ANOError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise ANOError("TENANT_MIGRATION_STORAGE_FAILURE", "atomic tenant migration failed") from exc
        finally:
            connection.close()


class SqliteBackupManager:
    """Online SQLite backup and fail-closed restore with content and database integrity checks."""

    def __init__(self, store: SqliteTenantStateStore) -> None:
        self.store = store

    @staticmethod
    def _file_hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"

    @staticmethod
    def _integrity(path: Path) -> None:
        connection = sqlite3.connect(path)
        try:
            result = connection.execute("PRAGMA integrity_check").fetchone()
        finally:
            connection.close()
        if result is None or result[0] != "ok":
            raise ANOError("BACKUP_DATABASE_CORRUPT", "SQLite integrity check failed")

    def create(self, backup_path: str | Path) -> dict[str, Any]:
        target = Path(backup_path)
        if target.exists():
            raise ANOError("BACKUP_TARGET_EXISTS", "backup target already exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        source = self.store._connect()
        destination = sqlite3.connect(target)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        self._integrity(target)
        size = target.stat().st_size
        manifest = {
            "backup_id": new_id("bak"), "schema_version": "0.4.0", "engine": "sqlite",
            "created_at": utc_now(), "database_hash": self._file_hash(target), "size_bytes": size,
            "integrity_check": "ok",
        }
        self.store.catalog.validate("sqlite-backup-manifest", manifest)
        return manifest

    def restore(self, backup_path: str | Path, manifest: dict[str, Any], target_path: str | Path) -> None:
        source_path = Path(backup_path)
        target = Path(target_path)
        self.store.catalog.validate("sqlite-backup-manifest", manifest)
        if not source_path.is_file() or source_path.stat().st_size != manifest["size_bytes"]:
            raise ANOError("BACKUP_CONTENT_MISMATCH", "backup file size differs from its manifest")
        if self._file_hash(source_path) != manifest["database_hash"]:
            raise ANOError("BACKUP_CONTENT_MISMATCH", "backup file hash differs from its manifest")
        self._integrity(source_path)
        if target.exists():
            raise ANOError("RESTORE_TARGET_EXISTS", "restore target must not already exist")
        target.parent.mkdir(parents=True, exist_ok=True)
        source = sqlite3.connect(source_path)
        destination = sqlite3.connect(target)
        try:
            source.backup(destination)
        except Exception:
            destination.close()
            source.close()
            if target.exists():
                target.unlink()
            raise
        else:
            destination.close()
            source.close()
        self._integrity(target)

