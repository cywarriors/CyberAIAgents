"""Anomaly query endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Query

from threat_detection_agent.api.dependencies import get_store
from threat_detection_agent.api.schemas import AnomalyResponse

router = APIRouter(prefix="/api/v1/anomalies", tags=["anomalies"])


@router.get("", response_model=list[AnomalyResponse])
async def list_anomalies(
    entity_type: str | None = None,
    anomaly_type: str | None = None,
    min_score: float | None = Query(None, ge=0.0, le=1.0),
):
    store = get_store()
    items = list(store.anomalies.values())
    if entity_type:
        items = [a for a in items if a.get("entity_type") == entity_type]
    if anomaly_type:
        items = [a for a in items if a.get("anomaly_type") == anomaly_type]
    if min_score is not None:
        items = [a for a in items if a.get("anomaly_score", 0) >= min_score]
    items.sort(key=lambda a: a.get("anomaly_score", 0), reverse=True)
    return [AnomalyResponse(**a) for a in items]


@router.post("", response_model=AnomalyResponse, status_code=201)
async def create_anomaly(
    anomaly_type: str = "unknown",
    anomaly_score: float = 0.5,
    baseline_value: float = 0.0,
    observed_value: float = 0.0,
    entity_type: str = "host",
    entity_id: str = "",
    description: str = "",
):
    """Create anomaly record (for testing / manual injection)."""
    store = get_store()
    aid = f"ANM-{uuid.uuid4().hex[:8]}"
    anomaly = {
        "anomaly_id": aid,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "anomaly_type": anomaly_type,
        "anomaly_score": anomaly_score,
        "baseline_value": baseline_value,
        "observed_value": observed_value,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "description": description,
    }
    store.anomalies[aid] = anomaly
    return AnomalyResponse(**anomaly)
