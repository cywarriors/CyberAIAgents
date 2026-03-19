"""Alert routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..dependencies import get_store
from ..store import InMemoryStore

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("")
def list_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    store: InMemoryStore = Depends(get_store),
) -> dict:
    items = store.get_alerts(limit=limit, offset=offset)
    total = store.count_alerts()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{alert_id}")
def get_alert(alert_id: str, store: InMemoryStore = Depends(get_store)) -> dict:
    for a in store.get_alerts(limit=10000):
        if a.get("alert_id") == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")
