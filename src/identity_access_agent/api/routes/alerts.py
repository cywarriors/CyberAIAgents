"""Identity alert endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from identity_access_agent.api.dependencies import get_store
from identity_access_agent.api.schemas import AlertResponse, FeedbackRequest

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List identity alerts with optional filters."""
    store = get_store()
    items = list(store.alerts.values())
    if severity:
        items = [a for a in items if a.get("severity") == severity]
    if status:
        items = [a for a in items if a.get("status") == status]
    items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return items[offset : offset + limit]


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str):
    """Retrieve a single alert by ID."""
    store = get_store()
    alert = store.alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/{alert_id}/feedback")
async def submit_feedback(alert_id: str, body: FeedbackRequest):
    """Submit analyst feedback on an alert (FR-10)."""
    store = get_store()
    alert = store.alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    from datetime import datetime, timezone

    feedback_entry = {
        "alert_id": alert_id,
        "analyst_id": body.analyst_id,
        "verdict": body.verdict,
        "notes": body.notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    store.feedback.append(feedback_entry)
    alert["status"] = "reviewed"
    return {"message": "Feedback recorded", "alert_id": alert_id}


@router.post("/{alert_id}/close")
async def close_alert(alert_id: str):
    """Close an alert."""
    store = get_store()
    alert = store.alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert["status"] = "closed"
    return {"message": "Alert closed", "alert_id": alert_id}
