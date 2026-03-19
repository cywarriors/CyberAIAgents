"""Interaction event routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..dependencies import get_store
from ..store import InMemoryStore

router = APIRouter(prefix="/api/v1/interactions", tags=["interactions"])


@router.get("")
def list_interactions(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    store: InMemoryStore = Depends(get_store),
) -> dict:
    items = store.get_interactions(limit=limit, offset=offset)
    total = store.count_interactions()
    return {"items": items, "total": total, "limit": limit, "offset": offset}
