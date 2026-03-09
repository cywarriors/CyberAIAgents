"""IngestTelemetryNode – consume events from queue / stream."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from threat_detection_agent.models.state import EventBatchState

logger = structlog.get_logger(__name__)


def ingest_telemetry(state: dict[str, Any]) -> dict[str, Any]:
    """
    Entry node: accepts pre-loaded raw events already placed in state
    by the caller (Kafka consumer, HTTP endpoint, or test harness).

    Assigns a batch ID and timestamps the batch.
    """
    raw_events: list[dict] = state.get("raw_events", [])
    batch_id = state.get("event_batch_id") or f"batch-{uuid.uuid4().hex[:12]}"

    logger.info(
        "ingest_telemetry",
        batch_id=batch_id,
        event_count=len(raw_events),
    )

    # Tag each event with the batch for traceability
    for evt in raw_events:
        evt.setdefault("_batch_id", batch_id)
        evt.setdefault("_ingested_at", datetime.now(timezone.utc).isoformat())

    return {"event_batch_id": batch_id, "raw_events": raw_events}
