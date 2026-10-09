from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

from ano_runtime import sha256_json

STANDARD_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = STANDARD_ROOT / "examples" / "v0.3.0"

F = TypeVar("F", bound=Callable[..., object])


def conformance(test_id: str) -> Callable[[F], F]:
    def decorate(function: F) -> F:
        setattr(function, "conformance_id", test_id)
        return function

    return decorate


def load_example(name: str) -> dict[str, Any]:
    with (EXAMPLES / f"{name}.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)


def fresh_grant() -> dict[str, Any]:
    grant = copy.deepcopy(load_example("permission-grant"))
    now = datetime.now(timezone.utc)
    grant["valid_from"] = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    grant["expires_at"] = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    return grant


def fresh_action() -> dict[str, Any]:
    action = copy.deepcopy(load_example("action"))
    action["status"] = "proposed"
    action["version"] = 1
    action["parameters_hash"] = sha256_json(action["parameters"])
    action["timeout_at"] = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat().replace("+00:00", "Z")
    return action


def fresh_memory(memory_id: str = "mem_demo_001") -> dict[str, Any]:
    memory = copy.deepcopy(load_example("memory"))
    memory["memory_id"] = memory_id
    now = datetime.now(timezone.utc)
    memory["created_at"] = now.isoformat().replace("+00:00", "Z")
    memory["last_confirmed_at"] = memory["created_at"]
    memory["review_at"] = (now + timedelta(days=30)).isoformat().replace("+00:00", "Z")
    return memory


def fresh_commitment(commitment_id: str = "com_demo_001") -> dict[str, Any]:
    commitment = copy.deepcopy(load_example("commitment"))
    commitment["commitment_id"] = commitment_id
    due = datetime.now(timezone.utc) - timedelta(seconds=1)
    commitment["due_at"] = due.isoformat().replace("+00:00", "Z")
    commitment["trigger"]["expression"] = commitment["due_at"]
    return commitment
