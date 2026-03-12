"""Alert CRUD and investigation endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from threat_detection_agent.api.dependencies import get_store
from threat_detection_agent.api.schemas import (
    AlertFeedback,
    AlertResponse,
    AlertUpdate,
    MessageResponse,
    PaginatedAlerts,
)

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("", response_model=PaginatedAlerts)
async def list_alerts(
    severity: list[str] | None = Query(None),
    status: str | None = None,
    source_type: str | None = None,
    entity_id: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    store = get_store()
    items = list(store.alerts.values())

    if severity:
        items = [a for a in items if a.get("severity") in severity]
    if status:
        items = [a for a in items if a.get("status") == status]
    if source_type:
        items = [a for a in items if a.get("source_type") == source_type]
    if entity_id:
        items = [a for a in items if entity_id in a.get("entity_ids", [])]
    if search:
        q = search.lower()
        items = [a for a in items if q in a.get("description", "").lower()]

    items.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    total = len(items)
    pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    return PaginatedAlerts(
        items=[AlertResponse(**a) for a in items[start : start + page_size]],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str):
    store = get_store()
    alert = store.alerts.get(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return AlertResponse(**alert)


@router.put("/{alert_id}", response_model=AlertResponse)
async def update_alert(alert_id: str, payload: AlertUpdate):
    store = get_store()
    alert = store.alerts.get(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    for k, v in payload.model_dump(exclude_none=True).items():
        alert[k] = v
    return AlertResponse(**alert)


@router.post("/{alert_id}/feedback", response_model=MessageResponse)
async def submit_feedback(alert_id: str, payload: AlertFeedback):
    store = get_store()
    if alert_id not in store.alerts:
        raise HTTPException(404, "Alert not found")
    store.feedback.append(
        {
            "alert_id": alert_id,
            "analyst_id": payload.analyst_id,
            "verdict": payload.verdict.value,
            "comment": payload.comment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    return MessageResponse(message="Feedback recorded")


@router.post("", response_model=AlertResponse, status_code=201)
async def create_alert(
    severity: str = "Medium",
    confidence: int = 50,
    source_type: str = "rule",
    description: str = "",
):
    """Create a new alert (used for testing / manual injection)."""
    store = get_store()
    aid = f"ALR-{uuid.uuid4().hex[:8]}"
    alert = {
        "alert_id": aid,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "confidence": confidence,
        "source_type": source_type,
        "description": description,
        "status": "new",
        "mitre_technique_ids": [],
        "mitre_tactics": [],
        "entity_ids": [],
        "matched_event_ids": [],
        "evidence": [],
        "analyst_notes": "",
        "related_alert_ids": [],
    }
    store.alerts[aid] = alert
    return AlertResponse(**alert)
