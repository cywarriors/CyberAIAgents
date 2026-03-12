"""IngestAlertNode – consume alerts from SIEM/EDR queue (§12.2)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def ingest_alert(state: dict[str, Any]) -> dict[str, Any]:
    """
    Entry node: accepts pre-loaded raw alerts already placed in state
    by the caller (Kafka consumer, HTTP endpoint, or test harness).

    Assigns a triage batch ID and timestamps each alert (FR-01).
    """
    raw_alerts: list[dict] = state.get("raw_alerts", [])
    batch_id = state.get("triage_batch_id") or f"triage-{uuid.uuid4().hex[:12]}"

    logger.info(
        "ingest_alert",
        batch_id=batch_id,
        alert_count=len(raw_alerts),
    )

    for alert in raw_alerts:
        alert.setdefault("_batch_id", batch_id)
        alert.setdefault("_ingested_at", datetime.now(timezone.utc).isoformat())
        # Ensure each alert has an ID
        alert.setdefault("alert_id", f"alert-{uuid.uuid4().hex[:12]}")

    return {"triage_batch_id": batch_id, "raw_alerts": raw_alerts}
