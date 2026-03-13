"""Recommendation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query

from identity_access_agent.api.dependencies import get_store
from identity_access_agent.api.schemas import RecommendationResponse

router = APIRouter(prefix="/api/v1/recommendations", tags=["recommendations"])


@router.get("", response_model=list[RecommendationResponse])
async def list_recommendations(
    control: str | None = None,
    risk_level: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List control recommendations."""
    store = get_store()
    items = list(store.recommendations.values())
    if control:
        items = [r for r in items if r.get("control") == control]
    if risk_level:
        items = [r for r in items if r.get("risk_level") == risk_level]
    items.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return items[offset : offset + limit]
