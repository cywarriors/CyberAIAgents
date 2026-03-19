"""Threat actor endpoints."""

from __future__ import annotations

import math
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from threat_intelligence_agent.api.dependencies import get_store
from threat_intelligence_agent.api.schemas import ActorListResponse, ActorResponse

router = APIRouter(prefix="/api/v1/actors", tags=["actors"])


@router.get("", response_model=ActorListResponse)
async def list_actors(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
) -> ActorListResponse:
    store = get_store()
    items = list(store.actors)
    if search:
        q = search.lower()
        items = [
            a for a in items
            if q in a.get("name", "").lower()
            or any(q in alias.lower() for alias in a.get("aliases", []))
        ]

    total = len(items)
    pages = max(math.ceil(total / page_size), 1)
    start = (page - 1) * page_size
    paged = items[start : start + page_size]

    return ActorListResponse(
        items=[ActorResponse(**a) for a in paged],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{actor_id}", response_model=ActorResponse)
async def get_actor(actor_id: str) -> ActorResponse:
    store = get_store()
    for a in store.actors:
        if a.get("actor_id") == actor_id:
            return ActorResponse(**a)
    raise HTTPException(404, "Actor not found")
