from __future__ import annotations

import argparse
import json
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
    ANOError, PostgresDistributedAdapterPlan, SchemaCatalog,
    SqliteDistributedOperationStore, __version__, new_id, utc_now,
)
from run_conformance import implementation_source_hash  # noqa: E402


def run(path: Path, catalog: SchemaCatalog) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "status": "passed" if passed else "failed", "detail": detail})

    now = datetime.now(timezone.utc)
    store = SqliteDistributedOperationStore(path, catalog)
    capabilities = store.capabilities()
    check(
        "capability_truthfulness",
        capabilities["runtime_verified"] and capabilities["multi_process"] and not capabilities["multi_host"],
        "SQLite declares verified multi-process semantics and denies multi-host support",
    )
    alpha = store.execute_operation(
        "tenant_alpha", "operation_demo_alpha", {"version": 1},
        [{"topic": "evolution_events", "payload": {"tenant": "alpha"}}], now=now,
    )
    alpha_replay = store.execute_operation(
        "tenant_alpha", "operation_demo_alpha", {"version": 1},
        [{"topic": "evolution_events", "payload": {"tenant": "alpha"}}], now=now,
    )
    check(
        "transactional_outbox",
        alpha_replay["idempotent_replay"]
        and alpha["messages"][0]["message_id"] == alpha_replay["messages"][0]["message_id"],
        "operation state and original message replay share one transaction",
    )
    beta = store.execute_operation(
        "tenant_beta", "operation_demo_beta", {"version": 1},
        [{"topic": "evolution_events", "payload": {"tenant": "beta"}}], now=now,
    )
    first_lease = store.acquire_lease(
        "queue_evolution", "node_alpha", ttl_seconds=5, now=now,
    )
    beta_claim = store.claim_next(
        first_lease, ["evolution_events"], ["tenant_beta"], claim_ttl_seconds=5, now=now,
    )
    check(
        "tenant_scoped_claim",
        beta_claim["message_id"] == beta["messages"][0]["message_id"]
        and store.message(alpha["messages"][0]["message_id"])["status"] == "pending",
        "worker claim could not cross its explicit tenant scope",
    )
    second_lease = store.acquire_lease(
        "queue_evolution", "node_beta", ttl_seconds=30, now=now + timedelta(seconds=6),
    )
    observed = "NO_ERROR"
    try:
        store.complete(
            first_lease, beta_claim["message_id"], "consumer_projection", {"applied": "stale"},
            now=now + timedelta(seconds=6),
        )
    except ANOError as exc:
        observed = exc.code
    check("epoch_fencing", observed == "DISTRIBUTED_FENCE_REJECTED", f"observed={observed}")
    reclaimed = store.claim_next(
        second_lease, ["evolution_events"], ["tenant_beta"], now=now + timedelta(seconds=6),
    )
    check(
        "expired_claim_recovery",
        reclaimed["message_id"] == beta_claim["message_id"] and reclaimed["attempts"] == 2,
        "new epoch reclaimed the expired claim without creating a second message",
    )
    effect = {"projection": "beta-applied", "version": 1}
    receipt = store.complete(
        second_lease, reclaimed["message_id"], "consumer_projection", effect,
        now=now + timedelta(seconds=7),
    )
    check(
        "atomic_inbox_effect",
        store.effect("consumer_projection", reclaimed["message_id"]) == effect
        and store.message(reclaimed["message_id"])["status"] == "delivered",
        "inbox receipt, database effect, and delivery status committed atomically",
    )
    replay = store.complete(
        second_lease, reclaimed["message_id"], "consumer_projection", effect,
        now=now + timedelta(hours=1),
    )
    check(
        "uncertain_commit_replay",
        replay["idempotent_replay"] and replay["receipt_id"] == receipt["receipt_id"],
        "post-commit retry returned the original receipt without reapplying the effect",
    )
    alpha_claim = store.claim_next(
        second_lease, ["evolution_events"], ["tenant_alpha"], claim_ttl_seconds=2,
        now=now + timedelta(seconds=8),
    )
    restarted = SqliteDistributedOperationStore(path, catalog)
    recovery = restarted.recover(now=now + timedelta(seconds=11))
    check(
        "crash_restart_requeue",
        recovery["requeued"] == 1
        and restarted.message(alpha_claim["message_id"])["status"] == "pending",
        "expired in-flight claim returned to pending after restart",
    )
    poison = restarted.execute_operation(
        "tenant_alpha", "operation_demo_poison", {"version": 1},
        [{"topic": "poison_events", "payload": {"poison": True}}], max_attempts=1,
        now=now + timedelta(seconds=11),
    )["messages"][0]
    poison_claim = restarted.claim_next(
        second_lease, ["poison_events"], ["tenant_alpha"], now=now + timedelta(seconds=12),
    )
    poison_status = restarted.fail(
        second_lease, poison_claim["message_id"], "deterministic poison payload",
        now=now + timedelta(seconds=12),
    )
    check(
        "bounded_dead_letter",
        poison_status == "dead_letter" and restarted.message(poison["message_id"])["status"] == "dead_letter",
        "poison message stopped retrying at its attempt limit",
    )
    postgres = PostgresDistributedAdapterPlan.capabilities(catalog)
    check(
        "postgres_claim_contract",
        "FOR UPDATE SKIP LOCKED" in PostgresDistributedAdapterPlan.CLAIM_SQL
        and any("JSONB" in statement for statement in PostgresDistributedAdapterPlan.ddl()),
        "PostgreSQL plan uses JSONB and non-blocking row claims",
    )
    check(
        "postgres_nonclaim", not postgres["runtime_verified"] and not postgres["multi_host"],
        "missing local PostgreSQL runtime remains explicit rather than simulated as passed",
    )
    return {
        "report_id": new_id("dar"), "schema_version": "0.5.0",
        "implementation_version": __version__, "implementation_source_hash": implementation_source_hash(),
        "generated_at": utc_now(), "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "checks": checks, "delivered_message_id": reclaimed["message_id"],
        "final_epoch": second_lease["epoch"], "postgres_runtime_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ANO 0.5 distributed delivery and recovery acceptance")
    parser.add_argument("--output", default=str(ROOT / "reports" / "v050-distributed-acceptance.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.5.0")
    with tempfile.TemporaryDirectory() as directory_name:
        report = run(Path(directory_name) / "distributed.db", catalog)
    catalog.validate("distributed-acceptance-report", report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "output": str(output)}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
