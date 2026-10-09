from __future__ import annotations

import argparse
import json
import secrets
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    ANOError, Ed25519IdentityIssuer, InMemoryKmsProvider, SchemaCatalog,
    SqliteBackupManager, SqliteExternalIdentityVerifier, SqliteLeaseCoordinator,
    SqliteSloMonitor, SqliteTenantKeyManager, SqliteTenantMigrationManager,
    SqliteTenantQuotaManager, SqliteTenantStateStore, TenantAccessBoundary,
    __version__, new_id, utc_now,
)
from run_conformance import implementation_source_hash  # noqa: E402


def run(directory: Path, catalog: SchemaCatalog) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "status": "passed" if passed else "failed", "detail": detail})

    now = datetime.now(timezone.utc)
    boundary = TenantAccessBoundary(
        catalog, {"principal_alpha": "tenant_alpha"}, secret=secrets.token_bytes(32),
    )
    source_path = directory / "source.db"
    provider = InMemoryKmsProvider()
    key_manager = SqliteTenantKeyManager(source_path, catalog, provider)
    source = SqliteTenantStateStore(source_path, catalog, boundary, key_manager=key_manager)

    issuer = Ed25519IdentityIssuer(catalog, "https://idp.ano.local", "identity_key_rc1")
    identity = SqliteExternalIdentityVerifier(
        source_path, catalog, boundary, expected_issuer="https://idp.ano.local",
        expected_audience="ano-production-kernel", trusted_keys={"identity_key_rc1": issuer.public_key},
    )
    assertion = issuer.issue("principal_alpha", "ano-production-kernel", now=now)
    session = identity.verify_and_open(assertion, now=now)
    check("external_identity", session.tenant_id == "tenant_alpha", "signed external subject resolved to its tenant boundary")

    quota = SqliteTenantQuotaManager(source_path, catalog)
    quota.configure("tenant_alpha", {"operations": 3, "model_tokens": 1000})
    charged = quota.consume(
        "tenant_alpha", "operation_rc_001", {"operations": 1, "model_tokens": 100}, now=now,
    )
    replay = quota.consume(
        "tenant_alpha", "operation_rc_001", {"operations": 1, "model_tokens": 100}, now=now,
    )
    check("quota_idempotency", replay["idempotent_replay"] and charged["receipt_id"] == replay["receipt_id"], "retry was not double charged")

    leases = SqliteLeaseCoordinator(source_path, catalog)
    lease = leases.acquire("organism_alpha", "worker_alpha", now=now)
    leases.assert_fence(lease, now=now)
    check("durable_fence", lease["fencing_token"] == 1, "exclusive mutation lease carries a durable fencing token")

    secret = "rc-secret-must-be-ciphertext"
    source.put(
        session, "organisms", "organism_alpha", {"stage": "rc", "secret": secret},
        expected_version=0, idempotency_key="idem_rc_state_001",
    )
    connection = sqlite3.connect(source_path)
    try:
        payload_json = connection.execute(
            "SELECT payload_json FROM tenant_objects WHERE tenant_id = ?", ("tenant_alpha",),
        ).fetchone()[0]
    finally:
        connection.close()
    check("encrypted_state", secret not in payload_json, "tenant payload is ciphertext at rest")

    rotation = key_manager.rotate_tenant_key("tenant_alpha")
    source.put(
        session, "organisms", "organism_alpha", {"stage": "rc-ready", "secret": secret},
        expected_version=1, idempotency_key="idem_rc_state_002",
    )
    check("key_rotation", rotation["new_key_version"] == 2 and source.get(
        session, "organisms", "organism_alpha",
    )["encryption"]["key_version"] == 2, "new writes are pinned to the rotated tenant key")

    audit_head = source.head_hash(session)
    assert audit_head is not None
    source.verify_tenant_log(session, expected_head_hash=audit_head)
    check("audit_binding", len(source.audit_events(session)) == 2, "state commits and tenant audit chain share one transaction boundary")

    target_path = directory / "target.db"
    target_provider = InMemoryKmsProvider("kms_target", "master_target")
    target_keys = SqliteTenantKeyManager(target_path, catalog, target_provider)
    target = SqliteTenantStateStore(target_path, catalog, boundary, key_manager=target_keys)
    migration_source = SqliteTenantMigrationManager(source)
    transfer_key = secrets.token_bytes(32)
    envelope = migration_source.transfer.encrypt_export(session, transfer_key)
    imported = SqliteTenantMigrationManager(target).import_encrypted(session, envelope, transfer_key)
    check(
        "atomic_migration",
        imported["source_audit_head_hash"] == audit_head and target.head_hash(session) == audit_head,
        "encrypted transfer preserved state, audit history and idempotency atomically",
    )

    backup_path = directory / "target.backup.db"
    backup_manager = SqliteBackupManager(target)
    backup_manifest = backup_manager.create(backup_path)
    restored_path = directory / "restored.db"
    backup_manager.restore(backup_path, backup_manifest, restored_path)
    restored_keys = SqliteTenantKeyManager(restored_path, catalog, target_provider)
    restored = SqliteTenantStateStore(restored_path, catalog, boundary, key_manager=restored_keys)
    check(
        "verified_restore", restored.get(session, "organisms", "organism_alpha")["payload"]["stage"] == "rc-ready"
        and restored.head_hash(session) == audit_head,
        "online backup restored encrypted state and its anchored audit head",
    )

    slo = SqliteSloMonitor(source_path, catalog)
    for offset, latency in enumerate((40, 45, 50, 55, 60)):
        slo.record("tenant_alpha", "production_kernel", success=True, latency_ms=latency, now=now + timedelta(milliseconds=offset))
    slo_report = slo.evaluate(
        "tenant_alpha", "production_kernel", window_seconds=60,
        availability_target=0.99, p95_latency_target_ms=100, now=now + timedelta(seconds=1),
    )
    check("slo_evaluation", slo_report["status"] == "met", "durable tenant-local observations meet configured SLO")

    destruction = target_keys.crypto_shred("tenant_alpha", "RC verified erasure drill")
    observed = "NO_ERROR"
    try:
        target.get(session, "organisms", "organism_alpha")
    except ANOError as exc:
        observed = exc.code
    check(
        "crypto_erasure", not destruction["recoverable"] and observed == "TENANT_KEY_DESTROYED",
        f"destroyed keys are unrecoverable; observed={observed}",
    )
    capabilities = source.capabilities()
    check(
        "capability_truthfulness", capabilities["portable_migration"] and not capabilities["multi_node"],
        "reference adapter declares implemented capabilities and explicitly denies multi-node support",
    )
    leases.release(lease)
    return {
        "report_id": new_id("pkr"), "schema_version": "0.4.0",
        "implementation_version": __version__, "implementation_source_hash": implementation_source_hash(),
        "generated_at": utc_now(), "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "checks": checks, "audit_head_hash": audit_head, "migration_package_hash": envelope["package_hash"],
        "backup_hash": backup_manifest["database_hash"], "slo_status": slo_report["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the ANO 0.4 RC production-kernel acceptance scenario")
    parser.add_argument("--output", default=str(ROOT / "reports" / "v040-production-kernel.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.4.0")
    with tempfile.TemporaryDirectory() as directory_name:
        report = run(Path(directory_name), catalog)
    catalog.validate("production-kernel-report", report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "output": str(output)}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
