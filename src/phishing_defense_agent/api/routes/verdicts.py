"""Verdict history endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from phishing_defense_agent.api.app import validate_id
from phishing_defense_agent.api.dependencies import get_store
from phishing_defense_agent.api.schemas import VerdictResponse

router = APIRouter(prefix="/api/v1/verdicts", tags=["verdicts"])


@router.get("", response_model=list[VerdictResponse])
async def list_verdicts(
    verdict: str | None = Query(None, pattern=r"^(clean|suspicious|malicious)$"),
    action: str | None = Query(None, pattern=r"^(allow|warn|quarantine|block)$"),
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(20, ge=1, le=100),
):
    """Verdict history with filtering."""
    store = get_store()
    items = list(store.verdicts.values())

    if verdict:
        items = [v for v in items if v.get("verdict") == verdict]
    if action:
        items = [v for v in items if v.get("action") == action]

    items.sort(key=lambda v: v.get("processed_at", ""), reverse=True)

    start = (page - 1) * page_size
    return items[start : start + page_size]


@router.get("/{message_id}", response_model=VerdictResponse)
async def get_verdict_detail(message_id: str):
    """Get detailed verdict for a specific email."""
    validate_id(message_id)
    store = get_store()
    if message_id not in store.verdicts:
        raise HTTPException(status_code=404, detail="Verdict not found")
    return store.verdicts[message_id]
