"""Brief endpoints — intelligence brief listing and detail."""

from __future__ import annotations

import math
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from threat_intelligence_agent.api.dependencies import get_store
from threat_intelligence_agent.api.schemas import BriefListResponse, BriefResponse

router = APIRouter(prefix="/api/v1/briefs", tags=["briefs"])


@router.get("", response_model=BriefListResponse)
async def list_briefs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    level: Optional[str] = None,
) -> BriefListResponse:
    store = get_store()
    items = list(store.briefs)
    if level:
        items = [b for b in items if b.get("level") == level]

    total = len(items)
    pages = max(math.ceil(total / page_size), 1)
    start = (page - 1) * page_size
    paged = items[start : start + page_size]

    return BriefListResponse(
        items=[BriefResponse(**b) for b in paged],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{brief_id}", response_model=BriefResponse)
async def get_brief(brief_id: str) -> BriefResponse:
    store = get_store()
    for b in store.briefs:
        if b.get("brief_id") == brief_id:
            return BriefResponse(**b)
    raise HTTPException(404, "Brief not found")
