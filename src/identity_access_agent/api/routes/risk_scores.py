"""Risk score endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from identity_access_agent.api.dependencies import get_store
from identity_access_agent.api.schemas import RiskScoreResponse

router = APIRouter(prefix="/api/v1/risk-scores", tags=["risk-scores"])


@router.get("", response_model=list[RiskScoreResponse])
async def list_risk_scores(
    risk_level: str | None = None,
    min_score: float | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List risk scores with optional filters."""
    store = get_store()
    items = list(store.risk_scores.values())
    if risk_level:
        items = [s for s in items if s.get("risk_level") == risk_level]
    if min_score is not None:
        items = [s for s in items if s.get("risk_score", 0) >= min_score]
    items.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return items[offset : offset + limit]


@router.get("/{user_id}", response_model=RiskScoreResponse)
async def get_user_risk_score(user_id: str):
    """Retrieve risk score for a specific user."""
    store = get_store()
    score = store.risk_scores.get(user_id)
    if not score:
        raise HTTPException(status_code=404, detail="Risk score not found for user")
    return score
