from __future__ import annotations

import argparse
import json
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    ANOError, SchemaCatalog, SqliteTenantStateStore, TenantAccessBoundary,
    __version__, new_id, utc_now,
)
from run_conformance import implementation_source_hash  # noqa: E402


def run(database: Path, catalog: SchemaCatalog) -> dict[str, Any]:
    boundary = TenantAccessBoundary(
        catalog, {"principal_alpha": "tenant_alpha", "principal_beta": "tenant_beta"},
        secret=secrets.token_bytes(32),
    )
    store = SqliteTenantStateStore(database, catalog, boundary)
    alpha = boundary.open_session("principal_alpha")
    beta = boundary.open_session("principal_beta")
    checks: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "status": "passed" if passed else "failed", "detail": detail})

    first = store.put(
        alpha, "goals", "goal_shared_001", {"owner": "alpha", "status": "active"},
        expected_version=0, idempotency_key="idem_demo_alpha",
    )
    store.put(
        beta, "goals", "goal_shared_001", {"owner": "beta", "status": "active"},
        expected_version=0, idempotency_key="idem_demo_beta",
    )
    check(
        "tenant_isolation",
        store.get(alpha, "goals", "goal_shared_001")["payload"]["owner"] == "alpha"
        and store.get(beta, "goals", "goal_shared_001")["payload"]["owner"] == "beta",
        "same object identifier resolves to tenant-local state",
    )
    replay = store.put(
        alpha, "goals", "goal_shared_001", {"owner": "alpha", "status": "active"},
        expected_version=0, idempotency_key="idem_demo_alpha",
    )
    check("idempotent_replay", replay["idempotent_replay"] and replay["transaction_id"] == first["transaction_id"], "retry returned the original transaction")
    observed = "NO_ERROR"
    try:
        store.put(
            alpha, "goals", "goal_shared_001", {"owner": "alpha", "status": "changed"},
            expected_version=0, idempotency_key="idem_demo_stale",
        )
    except ANOError as exc:
        observed = exc.code
    check("optimistic_conflict", observed == "STATE_CONFLICT", f"observed={observed}")
    check("atomic_audit", len(store.audit_events(alpha)) == 1 and len(store.audit_events(beta)) == 1, "each committed write produced exactly one tenant-local event")
    tenant_heads: dict[str, str] = {}
    export_hashes: dict[str, str] = {}
    for name, session in (("tenant_alpha", alpha), ("tenant_beta", beta)):
        head = store.head_hash(session)
        if head is None:
            raise RuntimeError("demo tenant has no audit head")
        store.verify_tenant_log(session, expected_head_hash=head)
        package = store.export_tenant(session)
        tenant_heads[name] = head
        export_hashes[name] = package["package_hash"]
    check("portable_export", len(set(export_hashes.values())) == 2, "tenant exports are schema-valid, self-hashed and independently scoped")
    return {
        "report_id": new_id("sar"), "schema_version": "0.4.0",
        "implementation_version": __version__, "implementation_source_hash": implementation_source_hash(),
        "generated_at": utc_now(),
        "database_engine": "sqlite",
        "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "checks": checks, "tenant_heads": tenant_heads, "export_hashes": export_hashes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the ANO 0.4 transactional multi-tenant storage demo")
    parser.add_argument("--database", help="Optional persistent SQLite database path")
    parser.add_argument("--output", default=str(ROOT / "reports" / "v040-storage-acceptance.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.4.0")
    if args.database:
        report = run(Path(args.database), catalog)
    else:
        with tempfile.TemporaryDirectory() as directory_name:
            report = run(Path(directory_name) / "tenant-state.db", catalog)
    catalog.validate("storage-acceptance-report", report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "output": str(output)}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
