"""Attack path endpoints – graph data for the visualizer."""

from __future__ import annotations

from fastapi import APIRouter, Query

from vapt_agent.api.dependencies import get_store
from vapt_agent.api.schemas import AttackPathResponse

router = APIRouter(prefix="/api/v1/attack-paths", tags=["attack-paths"])


@router.get("", response_model=list[AttackPathResponse])
async def list_attack_paths(
    engagement_id: str | None = None,
    min_risk: float = Query(0, ge=0, le=100),
):
    store = get_store()
    items = list(store.attack_paths.values())
    if engagement_id:
        items = [p for p in items if p.get("engagement_id") == engagement_id]
    if min_risk > 0:
        items = [p for p in items if p.get("composite_risk", 0) >= min_risk]
    items.sort(key=lambda p: p.get("composite_risk", 0), reverse=True)
    return items
