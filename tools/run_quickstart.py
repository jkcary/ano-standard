"""A local, no-API-key demonstration of restart, authorization and evidence.

The child exits abruptly after a completed write. This is not a power-loss,
partial-write or exactly-once external-delivery guarantee.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference" / "python"))

from ano_runtime import (  # noqa: E402
    ANOError, AppendOnlyEventStore, CommitmentService, PermissionEngine,
    PersistentScheduler, SchemaCatalog,
)

COMMITMENT = "com_quickstart"


def service(path: Path) -> CommitmentService:
    return CommitmentService(
        AppendOnlyEventStore(path), SchemaCatalog(ROOT / "schemas" / "v0.3.0"),
        ROOT / "state-machines" / "v0.3.0" / "commitment.machine.json",
    )


def prepare(path: Path) -> None:
    current = service(path)
    commitment = json.loads((ROOT / "examples/v0.3.0/commitment.json").read_text(encoding="utf-8"))
    commitment["commitment_id"] = COMMITMENT
    commitment["due_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    commitment["trigger"]["expression"] = commitment["due_at"]
    current.create(commitment)
    current.transition(COMMITMENT, "commitment.accepted", {
        "promisor_assigned", "trigger_present", "completion_condition_present", "capability_available",
    })
    current.transition(COMMITMENT, "commitment.scheduled", {"schedule_persisted"})
    # Deliberately skip normal interpreter teardown after the write has returned.
    os._exit(23)


def run(path: Path) -> dict:
    child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--prepare", str(path)], check=False)
    if child.returncode != 23:
        raise RuntimeError(f"unexpected child exit: {child.returncode}")
    restored = service(path)
    if restored.get(COMMITMENT)["status"] != "scheduled":
        raise RuntimeError("scheduled commitment was not recovered")
    deliveries: list[str] = []
    PersistentScheduler(restored, on_trigger=lambda event: deliveries.append(event["event_id"])).process_due()
    restored = service(path)
    PersistentScheduler(restored, on_trigger=lambda event: deliveries.append(event["event_id"])).process_due()
    if len(deliveries) != 1:
        raise RuntimeError("trigger replay was not suppressed")

    action = json.loads((ROOT / "examples/v0.3.0/action.json").read_text(encoding="utf-8"))
    try:
        PermissionEngine().authorize(action)
    except ANOError as exc:
        if exc.code != "AUTH_MISSING":
            raise
    else:
        raise RuntimeError("action without a grant was accepted")
    restored.transition(COMMITMENT, "commitment.blocked", {"block_reason_recorded", "review_time_set"},
                        evidence={"reason": "WAITING_FOR_PERMISSION", "review_at": datetime.now(timezone.utc).isoformat()})
    blocked = service(path).get(COMMITMENT)["status"] == "blocked"
    try:
        service(path).transition(COMMITMENT, "commitment.completed", {"verification_passed"})
    except ANOError:
        completion_rejected = True
    else:
        completion_rejected = False
    if not blocked or not completion_rejected:
        raise RuntimeError("blocked commitment incorrectly completed")
    return {
        "status": "passed", "child_exit_code": child.returncode,
        "scheduled_commitment_recovered": True, "trigger_deliveries": len(deliveries),
        "ungranted_action_rejected": True, "blocked_state_recovered": blocked,
        "completion_without_verification_rejected": completion_rejected,
        "final_state": service(path).get(COMMITMENT)["status"],
        "external_side_effects": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.prepare:
        prepare(args.prepare)
    with tempfile.TemporaryDirectory(prefix="ano-quickstart-") as directory:
        print(json.dumps(run(Path(directory) / "events.jsonl"), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
