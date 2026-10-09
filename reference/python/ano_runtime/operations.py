from __future__ import annotations

import json
import math
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .errors import ANOError
from .schema import SchemaCatalog
from .util import canonical_json, new_id, parse_timestamp, sha256_json, utc_now


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class SqliteLeaseCoordinator:
    """Durable exclusive leases with monotonically increasing fencing tokens."""

    def __init__(self, path: str | Path, catalog: SchemaCatalog) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS lease_counters (
                    resource_id TEXT PRIMARY KEY, last_fencing_token INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS durable_leases (
                    resource_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL, acquired_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL, expires_at TEXT NOT NULL
                );
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def acquire(
        self, resource_id: str, owner_id: str, *, ttl_seconds: int = 30, now: datetime | None = None,
    ) -> dict[str, Any]:
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise ANOError("LEASE_TTL_INVALID", "lease TTL must be between 1 and 3600 seconds")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                "SELECT * FROM durable_leases WHERE resource_id = ?", (resource_id,),
            ).fetchone()
            if active is not None and parse_timestamp(active["expires_at"]) > current:
                raise ANOError("LEASE_BUSY", "resource already has a live lease")
            counter = connection.execute(
                "SELECT last_fencing_token FROM lease_counters WHERE resource_id = ?", (resource_id,),
            ).fetchone()
            fencing_token = 1 if counter is None else int(counter["last_fencing_token"]) + 1
            connection.execute(
                """INSERT INTO lease_counters (resource_id, last_fencing_token) VALUES (?, ?)
                   ON CONFLICT(resource_id) DO UPDATE SET last_fencing_token = excluded.last_fencing_token""",
                (resource_id, fencing_token),
            )
            lease = {
                "lease_id": new_id("lse"), "schema_version": "0.4.0", "resource_id": resource_id,
                "owner_id": owner_id, "fencing_token": fencing_token, "acquired_at": _timestamp(current),
                "heartbeat_at": _timestamp(current), "expires_at": _timestamp(current + timedelta(seconds=ttl_seconds)),
            }
            self.catalog.validate("lease-grant", lease)
            connection.execute(
                """INSERT INTO durable_leases
                   (resource_id, lease_id, owner_id, fencing_token, acquired_at, heartbeat_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(resource_id) DO UPDATE SET lease_id=excluded.lease_id, owner_id=excluded.owner_id,
                   fencing_token=excluded.fencing_token, acquired_at=excluded.acquired_at,
                   heartbeat_at=excluded.heartbeat_at, expires_at=excluded.expires_at""",
                (
                    resource_id, lease["lease_id"], owner_id, fencing_token, lease["acquired_at"],
                    lease["heartbeat_at"], lease["expires_at"],
                ),
            )
            connection.commit()
            return lease
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def renew(
        self, lease: dict[str, Any], *, ttl_seconds: int = 30, now: datetime | None = None,
    ) -> dict[str, Any]:
        self.catalog.validate("lease-grant", lease)
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise ANOError("LEASE_TTL_INVALID", "lease TTL must be between 1 and 3600 seconds")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM durable_leases WHERE resource_id = ?", (lease["resource_id"],),
            ).fetchone()
            if (
                row is None or row["lease_id"] != lease["lease_id"]
                or int(row["fencing_token"]) != lease["fencing_token"]
                or parse_timestamp(row["expires_at"]) <= current
            ):
                raise ANOError("LEASE_STALE", "lease cannot be renewed after loss or expiry")
            renewed = {
                **lease, "heartbeat_at": _timestamp(current),
                "expires_at": _timestamp(current + timedelta(seconds=ttl_seconds)),
            }
            self.catalog.validate("lease-grant", renewed)
            connection.execute(
                "UPDATE durable_leases SET heartbeat_at = ?, expires_at = ? WHERE resource_id = ?",
                (renewed["heartbeat_at"], renewed["expires_at"], lease["resource_id"]),
            )
            connection.commit()
            return renewed
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def assert_fence(self, lease: dict[str, Any], *, now: datetime | None = None) -> None:
        self.catalog.validate("lease-grant", lease)
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM durable_leases WHERE resource_id = ?", (lease["resource_id"],),
            ).fetchone()
        finally:
            connection.close()
        if (
            row is None or row["lease_id"] != lease["lease_id"] or row["owner_id"] != lease["owner_id"]
            or int(row["fencing_token"]) != lease["fencing_token"]
            or parse_timestamp(row["expires_at"]) <= current
        ):
            raise ANOError("LEASE_FENCE_REJECTED", "stale or expired lease is fenced from mutation")

    def release(self, lease: dict[str, Any]) -> None:
        self.catalog.validate("lease-grant", lease)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            deleted = connection.execute(
                """DELETE FROM durable_leases WHERE resource_id = ? AND lease_id = ?
                   AND owner_id = ? AND fencing_token = ?""",
                (lease["resource_id"], lease["lease_id"], lease["owner_id"], lease["fencing_token"]),
            ).rowcount
            if deleted != 1:
                raise ANOError("LEASE_STALE", "only the current lease holder can release a lease")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class SqliteTenantQuotaManager:
    """Fixed-window tenant quotas with atomic, idempotent consumption receipts."""

    def __init__(self, path: str | Path, catalog: SchemaCatalog) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenant_quota_policies (
                    tenant_id TEXT PRIMARY KEY, window_seconds INTEGER NOT NULL, limits_json TEXT NOT NULL,
                    policy_hash TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tenant_quota_windows (
                    tenant_id TEXT NOT NULL, window_start INTEGER NOT NULL, usage_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, window_start)
                );
                CREATE TABLE IF NOT EXISTS tenant_quota_receipts (
                    tenant_id TEXT NOT NULL, operation_id TEXT NOT NULL, request_hash TEXT NOT NULL,
                    receipt_json TEXT NOT NULL, PRIMARY KEY (tenant_id, operation_id)
                );
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def configure(self, tenant_id: str, limits: dict[str, int], *, window_seconds: int = 60) -> dict[str, Any]:
        if not limits or any(not isinstance(value, int) or value < 0 for value in limits.values()):
            raise ANOError("QUOTA_POLICY_INVALID", "quota limits must be non-negative integers")
        if window_seconds < 1 or window_seconds > 86400:
            raise ANOError("QUOTA_POLICY_INVALID", "quota window must be between 1 second and 24 hours")
        policy = {
            "schema_version": "0.4.0", "tenant_id": tenant_id, "window_seconds": window_seconds,
            "limits": limits, "updated_at": utc_now(),
        }
        policy_hash = sha256_json(policy)
        connection = self._connect()
        try:
            connection.execute(
                """INSERT INTO tenant_quota_policies
                   (tenant_id, window_seconds, limits_json, policy_hash, updated_at) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(tenant_id) DO UPDATE SET window_seconds=excluded.window_seconds,
                   limits_json=excluded.limits_json, policy_hash=excluded.policy_hash, updated_at=excluded.updated_at""",
                (tenant_id, window_seconds, canonical_json(limits), policy_hash, policy["updated_at"]),
            )
            connection.commit()
        finally:
            connection.close()
        return {**policy, "policy_hash": policy_hash}

    def consume(
        self, tenant_id: str, operation_id: str, amounts: dict[str, int], *, now: datetime | None = None,
    ) -> dict[str, Any]:
        if not amounts or any(not isinstance(value, int) or value < 0 for value in amounts.values()):
            raise ANOError("QUOTA_REQUEST_INVALID", "quota consumption must use non-negative integers")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            policy = connection.execute(
                "SELECT * FROM tenant_quota_policies WHERE tenant_id = ?", (tenant_id,),
            ).fetchone()
            if policy is None:
                raise ANOError("QUOTA_POLICY_MISSING", "tenant quota policy is not configured")
            limits = json.loads(policy["limits_json"])
            if not set(amounts).issubset(limits):
                raise ANOError("QUOTA_DIMENSION_UNKNOWN", "quota request contains an unconfigured dimension")
            request_hash = sha256_json({"tenant_id": tenant_id, "operation_id": operation_id, "amounts": amounts})
            replay = connection.execute(
                "SELECT request_hash, receipt_json FROM tenant_quota_receipts WHERE tenant_id = ? AND operation_id = ?",
                (tenant_id, operation_id),
            ).fetchone()
            if replay is not None:
                if replay["request_hash"] != request_hash:
                    raise ANOError("QUOTA_IDEMPOTENCY_CONFLICT", "quota operation ID was reused with different amounts")
                receipt = json.loads(replay["receipt_json"])
                receipt["idempotent_replay"] = True
                connection.commit()
                return receipt
            seconds = int(policy["window_seconds"])
            window_start = int(current.timestamp()) // seconds * seconds
            usage_row = connection.execute(
                "SELECT usage_json FROM tenant_quota_windows WHERE tenant_id = ? AND window_start = ?",
                (tenant_id, window_start),
            ).fetchone()
            usage = {} if usage_row is None else json.loads(usage_row["usage_json"])
            projected = {key: int(usage.get(key, 0)) + int(amounts.get(key, 0)) for key in limits}
            exceeded = {key: projected[key] - limits[key] for key in limits if projected[key] > limits[key]}
            if exceeded:
                raise ANOError("QUOTA_EXCEEDED", f"tenant quota exceeded: {canonical_json(exceeded)}")
            connection.execute(
                """INSERT INTO tenant_quota_windows (tenant_id, window_start, usage_json) VALUES (?, ?, ?)
                   ON CONFLICT(tenant_id, window_start) DO UPDATE SET usage_json=excluded.usage_json""",
                (tenant_id, window_start, canonical_json(projected)),
            )
            receipt = {
                "receipt_id": new_id("qrc"), "schema_version": "0.4.0", "tenant_id": tenant_id,
                "operation_id": operation_id, "window_start": _timestamp(datetime.fromtimestamp(window_start, timezone.utc)),
                "window_seconds": seconds, "amounts": amounts, "usage": projected, "limits": limits,
                "accepted_at": _timestamp(current), "idempotent_replay": False,
            }
            self.catalog.validate("quota-consumption-receipt", receipt)
            connection.execute(
                "INSERT INTO tenant_quota_receipts (tenant_id, operation_id, request_hash, receipt_json) VALUES (?, ?, ?, ?)",
                (tenant_id, operation_id, request_hash, canonical_json(receipt)),
            )
            connection.commit()
            return receipt
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class SqliteSloMonitor:
    """Durable service-level observations and deterministic rolling-window evaluation."""

    def __init__(self, path: str | Path, catalog: SchemaCatalog) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS slo_observations (
                   observation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, service TEXT NOT NULL,
                   success INTEGER NOT NULL, latency_ms REAL NOT NULL, recorded_at TEXT NOT NULL)"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_slo_window ON slo_observations (tenant_id, service, recorded_at)"
            )
            connection.commit()
        finally:
            connection.close()

    def record(
        self, tenant_id: str, service: str, *, success: bool, latency_ms: float,
        now: datetime | None = None,
    ) -> str:
        if latency_ms < 0 or not math.isfinite(latency_ms):
            raise ANOError("SLO_OBSERVATION_INVALID", "latency must be finite and non-negative")
        observation_id = new_id("slo")
        recorded_at = _timestamp((now or datetime.now(timezone.utc)).astimezone(timezone.utc))
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "INSERT INTO slo_observations VALUES (?, ?, ?, ?, ?, ?)",
                (observation_id, tenant_id, service, int(success), latency_ms, recorded_at),
            )
            connection.commit()
        finally:
            connection.close()
        return observation_id

    def evaluate(
        self, tenant_id: str, service: str, *, window_seconds: int,
        availability_target: float, p95_latency_target_ms: float, now: datetime | None = None,
    ) -> dict[str, Any]:
        if window_seconds < 1 or not 0 <= availability_target <= 1 or p95_latency_target_ms < 0:
            raise ANOError("SLO_TARGET_INVALID", "SLO target configuration is invalid")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        since = _timestamp(current - timedelta(seconds=window_seconds))
        connection = sqlite3.connect(self.path)
        try:
            rows = connection.execute(
                """SELECT success, latency_ms FROM slo_observations
                   WHERE tenant_id = ? AND service = ? AND recorded_at >= ? AND recorded_at <= ?""",
                (tenant_id, service, since, _timestamp(current)),
            ).fetchall()
        finally:
            connection.close()
        sample_count = len(rows)
        successes = sum(int(row[0]) for row in rows)
        availability = 0.0 if not rows else successes / sample_count
        latencies = sorted(float(row[1]) for row in rows)
        p95 = 0.0 if not latencies else latencies[max(0, math.ceil(0.95 * len(latencies)) - 1)]
        report = {
            "report_id": new_id("slr"), "schema_version": "0.4.0", "tenant_id": tenant_id,
            "service": service, "window_start": since, "window_end": _timestamp(current),
            "sample_count": sample_count, "availability": availability, "p95_latency_ms": p95,
            "availability_target": availability_target, "p95_latency_target_ms": p95_latency_target_ms,
            "status": "met" if sample_count and availability >= availability_target and p95 <= p95_latency_target_ms else "violated",
        }
        self.catalog.validate("slo-evaluation-report", report)
        return report
