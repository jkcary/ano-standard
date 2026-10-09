from __future__ import annotations

import copy
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .errors import ANOError
from .schema import SchemaCatalog
from .util import canonical_json, new_id, parse_timestamp, sha256_json, utc_now


def _time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class SqliteDistributedOperationStore:
    """Transactional outbox/inbox with durable epoch fencing and crash-safe message recovery."""

    def __init__(self, path: str | Path, catalog: SchemaCatalog) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS distributed_epoch_counters (
                    resource_id TEXT PRIMARY KEY, last_epoch INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS distributed_worker_leases (
                    resource_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL, node_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL, acquired_at TEXT NOT NULL, heartbeat_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS distributed_operations (
                    operation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, request_hash TEXT NOT NULL,
                    state_json TEXT NOT NULL, committed_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS distributed_outbox (
                    message_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, operation_id TEXT NOT NULL,
                    topic TEXT NOT NULL, payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending','claimed','delivered','dead_letter')),
                    attempts INTEGER NOT NULL, max_attempts INTEGER NOT NULL, available_at TEXT NOT NULL,
                    claimed_by TEXT, claim_epoch INTEGER, claim_expires_at TEXT, created_at TEXT NOT NULL,
                    delivered_at TEXT, last_error TEXT,
                    FOREIGN KEY(operation_id) REFERENCES distributed_operations(operation_id)
                );
                CREATE TABLE IF NOT EXISTS distributed_inbox (
                    consumer_id TEXT NOT NULL, message_id TEXT NOT NULL, payload_hash TEXT NOT NULL,
                    effect_hash TEXT NOT NULL, receipt_json TEXT NOT NULL,
                    PRIMARY KEY(consumer_id, message_id)
                );
                CREATE TABLE IF NOT EXISTS distributed_effects (
                    consumer_id TEXT NOT NULL, message_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
                    effect_json TEXT NOT NULL, effect_hash TEXT NOT NULL, applied_at TEXT NOT NULL,
                    PRIMARY KEY(consumer_id, message_id)
                );
                CREATE INDEX IF NOT EXISTS idx_distributed_outbox_claim
                    ON distributed_outbox(status, available_at, topic, created_at);
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _lease(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "lease_id": row["lease_id"], "schema_version": "0.5.0", "resource_id": row["resource_id"],
            "node_id": row["node_id"], "epoch": int(row["epoch"]), "acquired_at": row["acquired_at"],
            "heartbeat_at": row["heartbeat_at"], "expires_at": row["expires_at"],
        }

    @staticmethod
    def _message(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "message_id": row["message_id"], "schema_version": "0.5.0", "tenant_id": row["tenant_id"],
            "operation_id": row["operation_id"], "topic": row["topic"],
            "payload": json.loads(row["payload_json"]), "payload_hash": row["payload_hash"],
            "status": row["status"], "attempts": int(row["attempts"]),
            "max_attempts": int(row["max_attempts"]), "available_at": row["available_at"],
            "claimed_by": row["claimed_by"], "claim_epoch": row["claim_epoch"],
            "claim_expires_at": row["claim_expires_at"], "created_at": row["created_at"],
            "delivered_at": row["delivered_at"], "last_error": row["last_error"],
        }

    def capabilities(self) -> dict[str, Any]:
        result = {
            "schema_version": "0.5.0", "adapter": "sqlite-distributed-reference", "engine": "sqlite",
            "transactional_outbox": True, "idempotent_inbox": True, "lease_epoch_fencing": True,
            "claim_recovery": True, "dead_letter": True, "skip_locked_claim": False,
            "runtime_verified": True, "multi_process": True, "multi_host": False,
        }
        self.catalog.validate("distributed-adapter-capabilities", result)
        return result

    def acquire_lease(
        self, resource_id: str, node_id: str, *, ttl_seconds: int = 30,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise ANOError("DISTRIBUTED_LEASE_TTL_INVALID", "lease TTL must be between 1 and 3600 seconds")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                "SELECT * FROM distributed_worker_leases WHERE resource_id = ?", (resource_id,),
            ).fetchone()
            if active is not None and parse_timestamp(active["expires_at"]) > current:
                raise ANOError("DISTRIBUTED_LEASE_BUSY", "resource has a live worker lease")
            counter = connection.execute(
                "SELECT last_epoch FROM distributed_epoch_counters WHERE resource_id = ?", (resource_id,),
            ).fetchone()
            epoch = 1 if counter is None else int(counter["last_epoch"]) + 1
            connection.execute(
                """INSERT INTO distributed_epoch_counters(resource_id,last_epoch) VALUES (?,?)
                   ON CONFLICT(resource_id) DO UPDATE SET last_epoch=excluded.last_epoch""",
                (resource_id, epoch),
            )
            timestamp = _time(current)
            lease = {
                "lease_id": new_id("dls"), "schema_version": "0.5.0", "resource_id": resource_id,
                "node_id": node_id, "epoch": epoch, "acquired_at": timestamp, "heartbeat_at": timestamp,
                "expires_at": _time(current + timedelta(seconds=ttl_seconds)),
            }
            self.catalog.validate("distributed-lease", lease)
            connection.execute(
                """INSERT INTO distributed_worker_leases
                   (resource_id,lease_id,node_id,epoch,acquired_at,heartbeat_at,expires_at)
                   VALUES (?,?,?,?,?,?,?) ON CONFLICT(resource_id) DO UPDATE SET
                   lease_id=excluded.lease_id,node_id=excluded.node_id,epoch=excluded.epoch,
                   acquired_at=excluded.acquired_at,heartbeat_at=excluded.heartbeat_at,
                   expires_at=excluded.expires_at""",
                (
                    resource_id, lease["lease_id"], node_id, epoch, timestamp,
                    timestamp, lease["expires_at"],
                ),
            )
            connection.commit()
            return lease
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _assert_lease(
        self, connection: sqlite3.Connection, lease: dict[str, Any], current: datetime,
    ) -> None:
        self.catalog.validate("distributed-lease", lease)
        row = connection.execute(
            "SELECT * FROM distributed_worker_leases WHERE resource_id = ?", (lease["resource_id"],),
        ).fetchone()
        if (
            row is None or row["lease_id"] != lease["lease_id"] or row["node_id"] != lease["node_id"]
            or int(row["epoch"]) != int(lease["epoch"]) or parse_timestamp(row["expires_at"]) <= current
        ):
            raise ANOError("DISTRIBUTED_FENCE_REJECTED", "worker lease is stale, replaced, or expired")

    def execute_operation(
        self, tenant_id: str, operation_id: str, state: dict[str, Any],
        publishes: list[dict[str, Any]], *, max_attempts: int = 3, now: datetime | None = None,
    ) -> dict[str, Any]:
        if not publishes or max_attempts < 1 or max_attempts > 100:
            raise ANOError("OUTBOX_REQUEST_INVALID", "operation needs messages and a valid attempt limit")
        normalized = []
        for item in publishes:
            if not isinstance(item.get("payload"), dict):
                raise ANOError("OUTBOX_REQUEST_INVALID", "outbox payload must be an object")
            normalized.append({"topic": item["topic"], "payload": item["payload"]})
        request_hash = sha256_json({
            "tenant_id": tenant_id, "operation_id": operation_id, "state": state,
            "publishes": normalized, "max_attempts": max_attempts,
        })
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT request_hash, state_json, committed_at FROM distributed_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise ANOError("OUTBOX_IDEMPOTENCY_CONFLICT", "operation ID is bound to another request")
                rows = connection.execute(
                    "SELECT * FROM distributed_outbox WHERE operation_id = ? ORDER BY created_at,message_id",
                    (operation_id,),
                ).fetchall()
                connection.commit()
                return {
                    "operation_id": operation_id, "tenant_id": tenant_id,
                    "state": json.loads(existing["state_json"]),
                    "messages": [self._message(row) for row in rows],
                    "committed_at": existing["committed_at"], "idempotent_replay": True,
                }
            committed_at = _time((now or datetime.now(timezone.utc)).astimezone(timezone.utc))
            connection.execute(
                "INSERT INTO distributed_operations VALUES (?,?,?,?,?)",
                (operation_id, tenant_id, request_hash, canonical_json(state), committed_at),
            )
            messages = []
            for item in normalized:
                payload_hash = sha256_json(item["payload"])
                message = {
                    "message_id": new_id("msg"), "schema_version": "0.5.0", "tenant_id": tenant_id,
                    "operation_id": operation_id, "topic": item["topic"], "payload": item["payload"],
                    "payload_hash": payload_hash, "status": "pending", "attempts": 0,
                    "max_attempts": max_attempts, "available_at": committed_at, "claimed_by": None,
                    "claim_epoch": None, "claim_expires_at": None, "created_at": committed_at,
                    "delivered_at": None, "last_error": None,
                }
                self.catalog.validate("outbox-message", message)
                connection.execute(
                    """INSERT INTO distributed_outbox
                       (message_id,tenant_id,operation_id,topic,payload_json,payload_hash,status,
                        attempts,max_attempts,available_at,claimed_by,claim_epoch,claim_expires_at,
                        created_at,delivered_at,last_error) VALUES (?,?,?,?,?,?,'pending',0,?,?,NULL,NULL,NULL,?,NULL,NULL)""",
                    (
                        message["message_id"], tenant_id, operation_id, message["topic"],
                        canonical_json(message["payload"]), payload_hash, max_attempts,
                        committed_at, committed_at,
                    ),
                )
                messages.append(message)
            connection.commit()
            return {
                "operation_id": operation_id, "tenant_id": tenant_id, "state": copy.deepcopy(state),
                "messages": messages, "committed_at": committed_at, "idempotent_replay": False,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def claim_next(
        self, lease: dict[str, Any], topics: list[str], tenant_ids: list[str], *, claim_ttl_seconds: int = 30,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        if not topics or not tenant_ids or claim_ttl_seconds < 1 or claim_ttl_seconds > 3600:
            raise ANOError("OUTBOX_CLAIM_INVALID", "topics, tenant scope, and claim TTL are required")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        current_text = _time(current)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_lease(connection, lease, current)
            connection.execute(
                """UPDATE distributed_outbox SET status='dead_letter', claimed_by=NULL,
                   claim_epoch=NULL, claim_expires_at=NULL
                   WHERE status='claimed' AND claim_expires_at <= ? AND attempts >= max_attempts""",
                (current_text,),
            )
            placeholders = ",".join("?" for _ in topics)
            tenant_placeholders = ",".join("?" for _ in tenant_ids)
            row = connection.execute(
                f"""SELECT * FROM distributed_outbox WHERE topic IN ({placeholders})
                    AND tenant_id IN ({tenant_placeholders})
                    AND attempts < max_attempts AND (
                        (status='pending' AND available_at <= ?) OR
                        (status='claimed' AND claim_expires_at <= ?)
                    ) ORDER BY created_at,message_id LIMIT 1""",
                (*topics, *tenant_ids, current_text, current_text),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            claim_expires = _time(current + timedelta(seconds=claim_ttl_seconds))
            connection.execute(
                """UPDATE distributed_outbox SET status='claimed', attempts=attempts+1,
                   claimed_by=?,claim_epoch=?,claim_expires_at=?,last_error=NULL WHERE message_id=?""",
                (lease["node_id"], lease["epoch"], claim_expires, row["message_id"]),
            )
            claimed = connection.execute(
                "SELECT * FROM distributed_outbox WHERE message_id = ?", (row["message_id"],),
            ).fetchone()
            assert claimed is not None
            message = self._message(claimed)
            self.catalog.validate("outbox-message", message)
            connection.commit()
            return message
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete(
        self, lease: dict[str, Any], message_id: str, consumer_id: str,
        effect: dict[str, Any], *, now: datetime | None = None,
    ) -> dict[str, Any]:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        effect_hash = sha256_json(effect)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM distributed_outbox WHERE message_id = ?", (message_id,),
            ).fetchone()
            if row is None:
                raise ANOError("OUTBOX_MESSAGE_UNKNOWN", "outbox message is unknown")
            replay = connection.execute(
                "SELECT payload_hash,effect_hash,receipt_json FROM distributed_inbox WHERE consumer_id=? AND message_id=?",
                (consumer_id, message_id),
            ).fetchone()
            if replay is not None:
                if replay["payload_hash"] != row["payload_hash"] or replay["effect_hash"] != effect_hash:
                    raise ANOError("INBOX_IDEMPOTENCY_CONFLICT", "message replay requested a different effect")
                receipt = json.loads(replay["receipt_json"])
                receipt["idempotent_replay"] = True
                self.catalog.validate("delivery-receipt", receipt)
                connection.commit()
                return receipt
            self._assert_lease(connection, lease, current)
            if (
                row["status"] != "claimed" or row["claimed_by"] != lease["node_id"]
                or int(row["claim_epoch"] or 0) != int(lease["epoch"])
                or row["claim_expires_at"] is None or parse_timestamp(row["claim_expires_at"]) <= current
            ):
                raise ANOError("OUTBOX_CLAIM_FENCED", "message claim is stale, expired, or owned by another epoch")
            delivered_at = _time(current)
            receipt = {
                "receipt_id": new_id("drc"), "schema_version": "0.5.0", "consumer_id": consumer_id,
                "message_id": message_id, "tenant_id": row["tenant_id"], "payload_hash": row["payload_hash"],
                "effect_hash": effect_hash, "delivered_at": delivered_at, "idempotent_replay": False,
            }
            self.catalog.validate("delivery-receipt", receipt)
            connection.execute(
                "INSERT INTO distributed_effects VALUES (?,?,?,?,?,?)",
                (consumer_id, message_id, row["tenant_id"], canonical_json(effect), effect_hash, delivered_at),
            )
            connection.execute(
                "INSERT INTO distributed_inbox VALUES (?,?,?,?,?)",
                (consumer_id, message_id, row["payload_hash"], effect_hash, canonical_json(receipt)),
            )
            connection.execute(
                """UPDATE distributed_outbox SET status='delivered',delivered_at=?,claimed_by=NULL,
                   claim_epoch=NULL,claim_expires_at=NULL WHERE message_id=?""",
                (delivered_at, message_id),
            )
            connection.commit()
            return receipt
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def fail(
        self, lease: dict[str, Any], message_id: str, error: str, *, retry_delay_seconds: int = 0,
        now: datetime | None = None,
    ) -> str:
        if not error or retry_delay_seconds < 0:
            raise ANOError("OUTBOX_FAILURE_INVALID", "failure reason and non-negative retry delay are required")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_lease(connection, lease, current)
            row = connection.execute(
                "SELECT * FROM distributed_outbox WHERE message_id = ?", (message_id,),
            ).fetchone()
            if (
                row is None or row["status"] != "claimed" or row["claimed_by"] != lease["node_id"]
                or int(row["claim_epoch"] or 0) != int(lease["epoch"])
            ):
                raise ANOError("OUTBOX_CLAIM_FENCED", "only the current claim owner can report failure")
            status = "dead_letter" if int(row["attempts"]) >= int(row["max_attempts"]) else "pending"
            connection.execute(
                """UPDATE distributed_outbox SET status=?,available_at=?,claimed_by=NULL,
                   claim_epoch=NULL,claim_expires_at=NULL,last_error=? WHERE message_id=?""",
                (
                    status, _time(current + timedelta(seconds=retry_delay_seconds)),
                    error[:2048], message_id,
                ),
            )
            connection.commit()
            return status
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def recover(self, *, now: datetime | None = None) -> dict[str, Any]:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        current_text = _time(current)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            expired = connection.execute(
                "SELECT message_id,attempts,max_attempts FROM distributed_outbox WHERE status='claimed' AND claim_expires_at <= ?",
                (current_text,),
            ).fetchall()
            requeued = dead_lettered = 0
            for row in expired:
                status = "dead_letter" if int(row["attempts"]) >= int(row["max_attempts"]) else "pending"
                connection.execute(
                    """UPDATE distributed_outbox SET status=?,available_at=?,claimed_by=NULL,
                       claim_epoch=NULL,claim_expires_at=NULL WHERE message_id=?""",
                    (status, current_text, row["message_id"]),
                )
                if status == "dead_letter":
                    dead_lettered += 1
                else:
                    requeued += 1
            counts = {row["status"]: int(row["count"]) for row in connection.execute(
                "SELECT status,COUNT(*) AS count FROM distributed_outbox GROUP BY status",
            ).fetchall()}
            report = {
                "report_id": new_id("drr"), "schema_version": "0.5.0", "recovered_at": current_text,
                "requeued": requeued, "dead_lettered": dead_lettered,
                "pending": counts.get("pending", 0), "claimed": counts.get("claimed", 0),
                "delivered": counts.get("delivered", 0), "dead_letter": counts.get("dead_letter", 0),
            }
            self.catalog.validate("delivery-recovery-report", report)
            connection.commit()
            return report
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def message(self, message_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM distributed_outbox WHERE message_id = ?", (message_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ANOError("OUTBOX_MESSAGE_UNKNOWN", "outbox message is unknown")
        message = self._message(row)
        self.catalog.validate("outbox-message", message)
        return message

    def effect(self, consumer_id: str, message_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT effect_json,effect_hash FROM distributed_effects WHERE consumer_id=? AND message_id=?",
                (consumer_id, message_id),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ANOError("DELIVERY_EFFECT_UNKNOWN", "delivery effect is unknown")
        effect = json.loads(row["effect_json"])
        if sha256_json(effect) != row["effect_hash"]:
            raise ANOError("DELIVERY_EFFECT_CORRUPT", "delivery effect integrity verification failed")
        return effect


class PostgresDistributedAdapterPlan:
    """Executable SQL contract for the future PostgreSQL adapter; not a runtime certification."""

    CLAIM_SQL = """SELECT message_id FROM distributed_outbox
        WHERE topic = ANY(%s) AND status = 'pending' AND available_at <= %s
        ORDER BY created_at,message_id FOR UPDATE SKIP LOCKED LIMIT 1"""

    @staticmethod
    def ddl() -> tuple[str, ...]:
        return (
            "CREATE TABLE distributed_epoch_counters (resource_id TEXT PRIMARY KEY, last_epoch BIGINT NOT NULL)",
            "CREATE TABLE distributed_worker_leases (resource_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL, node_id TEXT NOT NULL, epoch BIGINT NOT NULL, acquired_at TIMESTAMPTZ NOT NULL, heartbeat_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL)",
            "CREATE TABLE distributed_operations (operation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, request_hash TEXT NOT NULL, state_json JSONB NOT NULL, committed_at TIMESTAMPTZ NOT NULL)",
            "CREATE TABLE distributed_outbox (message_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, operation_id TEXT NOT NULL REFERENCES distributed_operations(operation_id), topic TEXT NOT NULL, payload_json JSONB NOT NULL, payload_hash TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, max_attempts INTEGER NOT NULL, available_at TIMESTAMPTZ NOT NULL, claimed_by TEXT, claim_epoch BIGINT, claim_expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL, delivered_at TIMESTAMPTZ, last_error TEXT)",
            "CREATE TABLE distributed_inbox (consumer_id TEXT NOT NULL, message_id TEXT NOT NULL, payload_hash TEXT NOT NULL, effect_hash TEXT NOT NULL, receipt_json JSONB NOT NULL, PRIMARY KEY(consumer_id,message_id))",
        )

    @staticmethod
    def capabilities(catalog: SchemaCatalog) -> dict[str, Any]:
        result = {
            "schema_version": "0.5.0", "adapter": "postgres-distributed-plan", "engine": "postgresql",
            "transactional_outbox": True, "idempotent_inbox": True, "lease_epoch_fencing": True,
            "claim_recovery": True, "dead_letter": True, "skip_locked_claim": True,
            "runtime_verified": False, "multi_process": False, "multi_host": False,
        }
        catalog.validate("distributed-adapter-capabilities", result)
        return result
