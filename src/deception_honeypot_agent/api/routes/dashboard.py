"""Dashboard summary route."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..dependencies import get_store
from ..store import InMemoryStore

router = APIRouter(prefix="/api/v1", tags=["dashboard"])


@router.get("/dashboard/deception")
def deception_dashboard(store: InMemoryStore = Depends(get_store)) -> dict:
    stats = store.get_statistics()
    coverage = store.get_coverage()
    recent_alerts = store.get_alerts(limit=5)
    recent_interactions = store.get_interactions(limit=10)
    return {
        "summary": stats,
        "coverage": coverage,
        "recent_alerts": recent_alerts,
        "recent_interactions": recent_interactions,
    }
