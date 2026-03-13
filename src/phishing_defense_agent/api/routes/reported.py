"""User-reported email queue endpoints (GUI-07)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from phishing_defense_agent.api.app import validate_id
from phishing_defense_agent.api.dependencies import get_store
from phishing_defense_agent.api.schemas import (
    ReportedEmailResponse,
    ReportedEmailReviewRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/reported", tags=["reported"])


@router.get("", response_model=list[ReportedEmailResponse])
async def list_reported_emails(
    processed: bool | None = Query(None),
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(20, ge=1, le=100),
):
    """User-reported suspicious emails awaiting analyst review."""
    store = get_store()
    items = list(store.reported.values())

    if processed is not None:
        items = [r for r in items if r.get("processed") == processed]

    items.sort(key=lambda r: r.get("report_timestamp", ""), reverse=True)

    start = (page - 1) * page_size
    return items[start : start + page_size]


@router.post("/{report_id}/review")
async def review_reported_email(report_id: str, body: ReportedEmailReviewRequest):
    """Analyst review of a user-reported email."""
    validate_id(report_id)
    store = get_store()
    if report_id not in store.reported:
        raise HTTPException(status_code=404, detail="Reported email not found")

    item = store.reported[report_id]
    item["analyst_verdict"] = body.verdict
    item["analyst_notes"] = body.notes
    item["processed"] = True
    item["reviewed_at"] = datetime.now(timezone.utc).isoformat()

    store.feedback.append({
        "message_id": item.get("reported_message_id"),
        "analyst_id": body.analyst_id,
        "verdict": body.verdict,
        "comment": body.notes,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    })

    logger.info("reported_email_reviewed: %s verdict=%s", report_id, body.verdict)
    return {"message": "Report reviewed", "report_id": report_id}
