"""Quarantine queue endpoints (GUI-02)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from phishing_defense_agent.api.app import validate_id
from phishing_defense_agent.api.dependencies import get_store
from phishing_defense_agent.api.schemas import (
    QuarantineDeleteRequest,
    QuarantineItemResponse,
    QuarantineReleaseRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/quarantine", tags=["quarantine"])


@router.get("", response_model=list[QuarantineItemResponse])
async def list_quarantine(
    status: str | None = Query(None, pattern=r"^(quarantined|released|deleted|pending_review)$"),
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(20, ge=1, le=100),
):
    """Paginated quarantine queue with filters."""
    store = get_store()
    items = list(store.quarantine.values())

    if status:
        items = [q for q in items if q.get("status") == status]

    items.sort(key=lambda q: q.get("quarantined_at", ""), reverse=True)

    start = (page - 1) * page_size
    return items[start : start + page_size]


@router.get("/{quarantine_id}", response_model=QuarantineItemResponse)
async def get_quarantine_item(quarantine_id: str):
    """Get quarantine item detail."""
    validate_id(quarantine_id)
    store = get_store()
    if quarantine_id not in store.quarantine:
        raise HTTPException(status_code=404, detail="Quarantine item not found")
    return store.quarantine[quarantine_id]


@router.post("/{quarantine_id}/release")
async def release_quarantine_item(quarantine_id: str, body: QuarantineReleaseRequest):
    """Release email from quarantine (FR-10)."""
    validate_id(quarantine_id)
    store = get_store()
    if quarantine_id not in store.quarantine:
        raise HTTPException(status_code=404, detail="Quarantine item not found")

    item = store.quarantine[quarantine_id]
    item["status"] = "released"
    item["reviewed_by"] = body.analyst_id
    item["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    item["release_justification"] = body.justification

    store.feedback.append({
        "message_id": item.get("message_id"),
        "analyst_id": body.analyst_id,
        "verdict": "false_positive",
        "comment": body.justification,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    })

    logger.info("quarantine_released: %s by %s", quarantine_id, body.analyst_id)
    return {"message": "Email released from quarantine", "quarantine_id": quarantine_id}


@router.delete("/{quarantine_id}")
async def delete_quarantine_item(quarantine_id: str, body: QuarantineDeleteRequest):
    """Permanently delete quarantined email."""
    validate_id(quarantine_id)
    store = get_store()
    if quarantine_id not in store.quarantine:
        raise HTTPException(status_code=404, detail="Quarantine item not found")

    item = store.quarantine[quarantine_id]
    item["status"] = "deleted"
    item["reviewed_by"] = body.analyst_id

    logger.info("quarantine_deleted: %s by %s", quarantine_id, body.analyst_id)
    return {"message": "Quarantined email deleted", "quarantine_id": quarantine_id}
