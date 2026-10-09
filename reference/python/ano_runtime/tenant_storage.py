from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .errors import ANOError
from .key_management import SqliteTenantKeyManager
from .schema import SchemaCatalog
from .util import canonical_json, new_id, parse_timestamp, sha256_json, utc_now


_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{2,127}$")


@dataclass(frozen=True)
class TenantSession:
    session_id: str
    schema_version: str
    tenant_id: str
    principal_id: str
    issued_at: str
    expires_at: str
    token: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


class TenantAccessBoundary:
    """Issue tenant-bound sessions from externally authenticated principal bindings."""

    def __init__(
        self, catalog: SchemaCatalog, principal_bindings: dict[str, str], *,
        secret: bytes, session_lifetime_seconds: int = 900,
    ) -> None:
        if len(secret) < 32:
            raise ANOError("TENANT_BOUNDARY_WEAK_SECRET", "tenant boundary secret must contain at least 32 bytes")
        if session_lifetime_seconds < 1 or session_lifetime_seconds > 86400:
            raise ANOError("TENANT_SESSION_LIFETIME_INVALID", "tenant session lifetime must be between 1 second and 24 hours")
        if not principal_bindings:
            raise ANOError("TENANT_BINDING_MISSING", "at least one principal-to-tenant binding is required")
        for principal_id, tenant_id in principal_bindings.items():
            self._validate_identifier(principal_id, "principal")
            self._validate_identifier(tenant_id, "tenant")
        self.catalog = catalog
        self._bindings = dict(principal_bindings)
        self._secret = bytes(secret)
        self._lifetime = session_lifetime_seconds

    @staticmethod
    def _validate_identifier(value: str, label: str) -> None:
        if not _IDENTIFIER.fullmatch(value):
            raise ANOError("TENANT_IDENTIFIER_INVALID", f"{label} identifier is invalid")

    def _token(self, material: dict[str, str]) -> str:
        digest = hmac.new(self._secret, canonical_json(material).encode("utf-8"), hashlib.sha256).hexdigest()
        return f"sha256:{digest}"

    def open_session(self, principal_id: str, *, now: datetime | None = None) -> TenantSession:
        tenant_id = self._bindings.get(principal_id)
        if tenant_id is None:
            raise ANOError("TENANT_ACCESS_DENIED", "principal has no tenant binding")
        issued = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        material = {
            "session_id": new_id("tsn"), "schema_version": "0.4.0",
            "tenant_id": tenant_id, "principal_id": principal_id,
            "issued_at": issued.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "expires_at": (issued + timedelta(seconds=self._lifetime)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }
        session = TenantSession(**material, token=self._token(material))
        self.catalog.validate("tenant-session", session.as_dict())
        return session

    def verify(self, session: TenantSession, *, now: datetime | None = None) -> str:
        material = session.as_dict()
        self.catalog.validate("tenant-session", material)
        token = material.pop("token")
        if not hmac.compare_digest(token, self._token(material)):
            raise ANOError("TENANT_SESSION_INVALID", "tenant session binding is invalid")
        expected_tenant = self._bindings.get(session.principal_id)
        if expected_tenant is None or expected_tenant != session.tenant_id:
            raise ANOError("TENANT_ACCESS_DENIED", "principal-to-tenant binding changed or was revoked")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if current < parse_timestamp(session.issued_at) or current >= parse_timestamp(session.expires_at):
            raise ANOError("TENANT_SESSION_EXPIRED", "tenant session is outside its validity interval")
        return session.tenant_id


class SqliteTenantStateStore:
    """Transactional multi-tenant reference store with optimistic concurrency and per-tenant audit chains."""

    def __init__(
        self, path: str | Path, catalog: SchemaCatalog, access_boundary: TenantAccessBoundary,
        *, key_manager: SqliteTenantKeyManager | None = None, busy_timeout_ms: int = 5000,
    ) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.access_boundary = access_boundary
        self.key_manager = key_manager
        if key_manager is not None and key_manager.path.resolve() != self.path.resolve():
            raise ANOError("TENANT_KEY_STORE_MISMATCH", "tenant key manager must use the state store database")
        self.busy_timeout_ms = busy_timeout_ms
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self.busy_timeout_ms / 1000, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def capabilities(self) -> dict[str, Any]:
        capabilities = {
            "schema_version": "0.4.0", "adapter": "sqlite-reference", "engine": "sqlite",
            "atomic_tenant_writes": True, "optimistic_concurrency": True,
            "tenant_audit_chain": True, "tenant_envelope_encryption": self.key_manager is not None,
            "portable_migration": True, "online_backup": True, "multi_node": False,
        }
        self.catalog.validate("storage-adapter-capabilities", capabilities)
        return capabilities

    @contextmanager
    def _connection(self) -> Any:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenant_objects (
                    tenant_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('active', 'deleted')),
                    payload_json TEXT,
                    payload_encoding TEXT NOT NULL DEFAULT 'plaintext-json',
                    payload_hash TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, namespace, object_id)
                );
                CREATE TABLE IF NOT EXISTS tenant_audit_events (
                    tenant_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    transaction_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    object_version INTEGER NOT NULL,
                    payload_hash TEXT NOT NULL,
                    previous_hash TEXT,
                    recorded_at TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, sequence),
                    UNIQUE (tenant_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS tenant_idempotency (
                    tenant_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_objects_scope
                    ON tenant_objects (tenant_id, namespace, status, object_id);
                """
            )
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(tenant_objects)").fetchall()}
            if "payload_encoding" not in columns:
                connection.execute(
                    "ALTER TABLE tenant_objects ADD COLUMN payload_encoding TEXT NOT NULL DEFAULT 'plaintext-json'"
                )

    @staticmethod
    def _validate_identifier(value: str, label: str) -> None:
        if not _IDENTIFIER.fullmatch(value):
            raise ANOError("TENANT_IDENTIFIER_INVALID", f"{label} identifier is invalid")

    @staticmethod
    def _event_hash(event: dict[str, Any]) -> str:
        material = copy.deepcopy(event)
        material.pop("record_hash", None)
        return sha256_json(material)

    def _tenant(self, session: TenantSession) -> str:
        return self.access_boundary.verify(session)

    def _replay_receipt(
        self, connection: sqlite3.Connection, tenant_id: str, idempotency_key: str,
        request_hash: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT request_hash, receipt_json FROM tenant_idempotency WHERE tenant_id = ? AND idempotency_key = ?",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise ANOError("IDEMPOTENCY_CONFLICT", "idempotency key was already used for a different tenant operation")
        try:
            receipt = json.loads(row["receipt_json"])
            stored_receipt = copy.deepcopy(receipt)
            self.catalog.validate("tenant-transaction-receipt", stored_receipt)
            event_row = connection.execute(
                "SELECT * FROM tenant_audit_events WHERE tenant_id = ? AND sequence = ?",
                (tenant_id, stored_receipt["event_sequence"]),
            ).fetchone()
            if event_row is None:
                raise ValueError("receipt event is missing")
            event = {key: event_row[key] for key in event_row.keys()} | {"schema_version": "0.4.0"}
            self.catalog.validate("tenant-audit-event", event)
            if event["record_hash"] != self._event_hash(event):
                raise ValueError("receipt event hash is invalid")
            if (
                stored_receipt["tenant_id"] != tenant_id
                or stored_receipt["idempotency_key"] != idempotency_key
                or event["transaction_id"] != stored_receipt["transaction_id"]
                or event["idempotency_key"] != idempotency_key
                or event["request_hash"] != request_hash
                or event["record_hash"] != stored_receipt["event_record_hash"]
                or event["namespace"] != stored_receipt["namespace"]
                or event["object_id"] != stored_receipt["object_id"]
                or event["object_version"] != stored_receipt["version"]
                or event["payload_hash"] != stored_receipt["payload_hash"]
            ):
                raise ValueError("receipt binding is invalid")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, ANOError) as exc:
            raise ANOError("TENANT_IDEMPOTENCY_CORRUPT", "tenant idempotency receipt integrity verification failed") from exc
        receipt["idempotent_replay"] = True
        self.catalog.validate("tenant-transaction-receipt", receipt)
        return receipt

    def _write(
        self, session: TenantSession, namespace: str, object_id: str, *,
        operation: str, payload: dict[str, Any] | None, expected_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant_id = self._tenant(session)
        self._validate_identifier(namespace, "namespace")
        self._validate_identifier(object_id, "object")
        self._validate_identifier(idempotency_key, "idempotency key")
        if expected_version < 0:
            raise ANOError("STATE_VERSION_INVALID", "expected version cannot be negative")
        if operation == "put" and not isinstance(payload, dict):
            raise ANOError("STATE_PAYLOAD_INVALID", "put requires an object payload")
        try:
            payload_hash = sha256_json(payload)
        except (TypeError, ValueError) as exc:
            raise ANOError("STATE_PAYLOAD_INVALID", "tenant payload must be canonical JSON") from exc
        request_hash = sha256_json({
            "tenant_id": tenant_id, "namespace": namespace, "object_id": object_id,
            "operation": operation, "payload_hash": payload_hash, "expected_version": expected_version,
        })
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay_receipt(connection, tenant_id, idempotency_key, request_hash)
            if replay is not None:
                connection.commit()
                return replay
            current = connection.execute(
                "SELECT version, status FROM tenant_objects WHERE tenant_id = ? AND namespace = ? AND object_id = ?",
                (tenant_id, namespace, object_id),
            ).fetchone()
            if operation == "delete" and (current is None or current["status"] == "deleted"):
                raise ANOError("OBJECT_NOT_FOUND", "cannot delete an absent tenant object")
            actual_version = 0 if current is None else int(current["version"])
            if actual_version != expected_version:
                raise ANOError("STATE_CONFLICT", f"expected version {expected_version}, observed {actual_version}")
            version = actual_version + 1
            committed_at = utc_now()
            status = "active" if operation == "put" else "deleted"
            if payload is None:
                payload_json = None
                payload_encoding = "tombstone"
            elif self.key_manager is None:
                payload_json = canonical_json(payload)
                payload_encoding = "plaintext-json"
            else:
                envelope = self.key_manager.encrypt_json(
                    tenant_id, namespace, object_id, version, payload, connection=connection,
                )
                payload_json = canonical_json(envelope)
                payload_encoding = "aes-256-gcm-envelope-v1"
            connection.execute(
                """
                INSERT INTO tenant_objects
                    (tenant_id, namespace, object_id, version, status, payload_json, payload_encoding, payload_hash, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, namespace, object_id) DO UPDATE SET
                    version = excluded.version, status = excluded.status, payload_json = excluded.payload_json,
                    payload_encoding = excluded.payload_encoding, payload_hash = excluded.payload_hash,
                    updated_at = excluded.updated_at
                """,
                (
                    tenant_id, namespace, object_id, version, status, payload_json, payload_encoding,
                    payload_hash, committed_at,
                ),
            )
            previous = connection.execute(
                "SELECT sequence, record_hash FROM tenant_audit_events WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
            sequence = 1 if previous is None else int(previous["sequence"]) + 1
            previous_hash = None if previous is None else str(previous["record_hash"])
            transaction_id = new_id("txn")
            event_material = {
                "event_id": new_id("tae"), "schema_version": "0.4.0", "tenant_id": tenant_id,
                "transaction_id": transaction_id, "idempotency_key": idempotency_key,
                "request_hash": request_hash,
                "sequence": sequence, "event_type": f"tenant.object.{operation}",
                "namespace": namespace, "object_id": object_id, "object_version": version,
                "payload_hash": payload_hash, "previous_hash": previous_hash, "recorded_at": committed_at,
            }
            event = {**event_material, "record_hash": self._event_hash(event_material)}
            self.catalog.validate("tenant-audit-event", event)
            connection.execute(
                """
                INSERT INTO tenant_audit_events
                (tenant_id, sequence, event_id, transaction_id, idempotency_key, request_hash,
                 event_type, namespace, object_id, object_version,
                 payload_hash, previous_hash, recorded_at, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id, sequence, event["event_id"], transaction_id, idempotency_key, request_hash,
                    event["event_type"], namespace, object_id,
                    version, payload_hash, previous_hash, committed_at, event["record_hash"],
                ),
            )
            receipt = {
                "transaction_id": transaction_id, "schema_version": "0.4.0", "tenant_id": tenant_id,
                "namespace": namespace, "object_id": object_id, "operation": operation,
                "previous_version": actual_version, "version": version, "payload_hash": payload_hash,
                "event_sequence": sequence, "event_record_hash": event["record_hash"],
                "committed_at": committed_at, "idempotency_key": idempotency_key,
                "idempotent_replay": False,
            }
            self.catalog.validate("tenant-transaction-receipt", receipt)
            connection.execute(
                "INSERT INTO tenant_idempotency (tenant_id, idempotency_key, request_hash, receipt_json) VALUES (?, ?, ?, ?)",
                (tenant_id, idempotency_key, request_hash, canonical_json(receipt)),
            )
            connection.commit()
            return copy.deepcopy(receipt)
        except ANOError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise ANOError("TENANT_STORAGE_FAILURE", "transactional tenant write failed") from exc
        finally:
            connection.close()

    def put(
        self, session: TenantSession, namespace: str, object_id: str, payload: dict[str, Any], *,
        expected_version: int, idempotency_key: str,
    ) -> dict[str, Any]:
        return self._write(
            session, namespace, object_id, operation="put", payload=payload,
            expected_version=expected_version, idempotency_key=idempotency_key,
        )

    def delete(
        self, session: TenantSession, namespace: str, object_id: str, *,
        expected_version: int, idempotency_key: str,
    ) -> dict[str, Any]:
        return self._write(
            session, namespace, object_id, operation="delete", payload=None,
            expected_version=expected_version, idempotency_key=idempotency_key,
        )

    def get(
        self, session: TenantSession, namespace: str, object_id: str, *, include_deleted: bool = False,
    ) -> dict[str, Any]:
        tenant_id = self._tenant(session)
        self._validate_identifier(namespace, "namespace")
        self._validate_identifier(object_id, "object")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT tenant_id, namespace, object_id, version, status, payload_json, payload_encoding,
                       payload_hash, updated_at
                FROM tenant_objects WHERE tenant_id = ? AND namespace = ? AND object_id = ?
                """,
                (tenant_id, namespace, object_id),
            ).fetchone()
            event_row = connection.execute(
                """SELECT * FROM tenant_audit_events
                    WHERE tenant_id = ? AND namespace = ? AND object_id = ?
                    ORDER BY object_version DESC LIMIT 1""",
                (tenant_id, namespace, object_id),
            ).fetchone()
            if row is None or (row["status"] == "deleted" and not include_deleted):
                raise ANOError("OBJECT_NOT_FOUND", "tenant object does not exist in this scope")
            try:
                encryption: dict[str, Any] | None = None
                if row["payload_json"] is None:
                    payload = None
                elif row["payload_encoding"] == "plaintext-json":
                    payload = json.loads(row["payload_json"])
                elif row["payload_encoding"] == "aes-256-gcm-envelope-v1":
                    if self.key_manager is None:
                        raise ANOError(
                            "TENANT_KEY_MANAGER_REQUIRED", "encrypted tenant state requires its key manager",
                        )
                    envelope = json.loads(row["payload_json"])
                    payload = self.key_manager.decrypt_json(
                        tenant_id, namespace, object_id, int(row["version"]), envelope, connection=connection,
                    )
                    encryption = {
                        "algorithm": envelope["algorithm"], "key_version": envelope["key_version"],
                        "encrypted_at": envelope["encrypted_at"],
                    }
                else:
                    raise ValueError("state payload encoding is unknown")
                result = {
                    "tenant_id": row["tenant_id"], "namespace": row["namespace"], "object_id": row["object_id"],
                    "schema_version": "0.4.0", "version": int(row["version"]), "status": row["status"],
                    "payload": payload, "payload_hash": row["payload_hash"], "updated_at": row["updated_at"],
                    "encryption": encryption,
                }
                self.catalog.validate("tenant-state-object", result)
                if result["payload_hash"] != sha256_json(result["payload"]) or event_row is None:
                    raise ValueError("state payload or event is invalid")
                event = {key: event_row[key] for key in event_row.keys()} | {"schema_version": "0.4.0"}
                self.catalog.validate("tenant-audit-event", event)
                expected_event_type = "tenant.object.put" if result["status"] == "active" else "tenant.object.delete"
                if (
                    event["record_hash"] != self._event_hash(event)
                    or event["tenant_id"] != tenant_id or event["namespace"] != namespace
                    or event["object_id"] != object_id or event["object_version"] != result["version"]
                    or event["payload_hash"] != result["payload_hash"] or event["recorded_at"] != result["updated_at"]
                    or event["event_type"] != expected_event_type
                ):
                    raise ValueError("state-to-audit binding is invalid")
            except ANOError as exc:
                if exc.code.startswith(("TENANT_KEY", "KMS_", "TENANT_DECRYPT", "TENANT_CIPHERTEXT")):
                    raise
                raise ANOError("TENANT_STATE_CORRUPT", "tenant state integrity verification failed") from exc
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise ANOError("TENANT_STATE_CORRUPT", "tenant state integrity verification failed") from exc
        return result

    def list_objects(
        self, session: TenantSession, namespace: str, *, include_deleted: bool = False,
    ) -> tuple[dict[str, Any], ...]:
        tenant_id = self._tenant(session)
        self._validate_identifier(namespace, "namespace")
        status_clause = "" if include_deleted else "AND status = 'active'"
        with self._connection() as connection:
            rows = connection.execute(
                f"""SELECT object_id FROM tenant_objects
                    WHERE tenant_id = ? AND namespace = ? {status_clause} ORDER BY object_id""",
                (tenant_id, namespace),
            ).fetchall()
        return tuple(self.get(session, namespace, str(row["object_id"]), include_deleted=include_deleted) for row in rows)

    def audit_events(self, session: TenantSession) -> tuple[dict[str, Any], ...]:
        tenant_id = self._tenant(session)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM tenant_audit_events WHERE tenant_id = ? ORDER BY sequence", (tenant_id,),
            ).fetchall()
        events = tuple({key: row[key] for key in row.keys()} | {"schema_version": "0.4.0"} for row in rows)
        for event in events:
            self.catalog.validate("tenant-audit-event", event)
        return events

    def verify_tenant_log(self, session: TenantSession, *, expected_head_hash: str | None = None) -> None:
        events = self.audit_events(session)
        previous_hash: str | None = None
        for expected_sequence, event in enumerate(events, start=1):
            if event["sequence"] != expected_sequence or event["previous_hash"] != previous_hash:
                raise ANOError("TENANT_AUDIT_CORRUPT", "tenant audit sequence or predecessor is invalid")
            if event["record_hash"] != self._event_hash(event):
                raise ANOError("TENANT_AUDIT_CORRUPT", "tenant audit record hash is invalid")
            previous_hash = str(event["record_hash"])
        if expected_head_hash is not None and previous_hash != expected_head_hash:
            raise ANOError("TENANT_AUDIT_TRUNCATED", "tenant audit head differs from its external anchor")

    def head_hash(self, session: TenantSession) -> str | None:
        events = self.audit_events(session)
        return None if not events else str(events[-1]["record_hash"])

    def export_tenant(self, session: TenantSession) -> dict[str, Any]:
        tenant_id = self._tenant(session)
        with self._connection() as connection:
            namespaces = [str(row["namespace"]) for row in connection.execute(
                "SELECT DISTINCT namespace FROM tenant_objects WHERE tenant_id = ? ORDER BY namespace", (tenant_id,),
            ).fetchall()]
            idempotency_rows = connection.execute(
                "SELECT idempotency_key, request_hash, receipt_json FROM tenant_idempotency WHERE tenant_id = ? ORDER BY idempotency_key",
                (tenant_id,),
            ).fetchall()
        objects = [item for namespace in namespaces for item in self.list_objects(session, namespace, include_deleted=True)]
        events = list(self.audit_events(session))
        idempotency_records = [{
            "tenant_id": tenant_id, "idempotency_key": row["idempotency_key"],
            "request_hash": row["request_hash"], "receipt": json.loads(row["receipt_json"]),
        } for row in idempotency_rows]
        for record in idempotency_records:
            self.catalog.validate("tenant-idempotency-record", record)
        material = {
            "package_id": new_id("tex"), "schema_version": "0.4.0", "tenant_id": tenant_id,
            "exported_at": utc_now(), "objects": objects, "audit_events": events,
            "idempotency_records": idempotency_records,
            "audit_head_hash": None if not events else events[-1]["record_hash"],
        }
        package = {**material, "package_hash": sha256_json(material)}
        self.catalog.validate("tenant-export-package", package)
        return package
