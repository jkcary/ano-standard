from __future__ import annotations

from typing import Any

from .util import new_id, utc_now


def build_event(
    event_type: str,
    actor_id: str,
    subject_ids: list[str],
    payload: dict[str, Any],
    *,
    event_time: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Build a schema-valid event while preserving event/observation time separation."""
    recorded_at = utc_now()
    event_id = new_id("evt")
    return {
        "event_id": event_id,
        "event_type": event_type,
        "schema_version": "0.3.0",
        "actor_id": actor_id,
        "subject_ids": subject_ids,
        "event_time": event_time,
        "observed_at": recorded_at,
        "recorded_at": recorded_at,
        "payload": payload,
        "epistemic_status": "observed",
        "confidence": 1.0,
        "sensitivity": "internal",
        "provenance": {
            "source_type": "system",
            "source_id": actor_id,
            "parent_ids": [causation_id] if causation_id else [],
            "observed_at": recorded_at,
        },
        "correlation_id": correlation_id or event_id,
        "causation_id": causation_id,
    }
