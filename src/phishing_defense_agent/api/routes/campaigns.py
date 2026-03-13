"""Campaign tracker endpoints (GUI-04)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from phishing_defense_agent.api.app import validate_id
from phishing_defense_agent.api.dependencies import get_store
from phishing_defense_agent.api.schemas import CampaignResponse

router = APIRouter(prefix="/api/v1/campaigns", tags=["campaigns"])


@router.get("", response_model=list[CampaignResponse])
async def list_campaigns(
    severity: str | None = Query(None, pattern=r"^(low|medium|high|critical)$"),
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(20, ge=1, le=100),
):
    """Phishing campaign clusters."""
    store = get_store()
    items = list(store.campaigns.values())

    if severity:
        items = [c for c in items if c.get("severity") == severity]

    items.sort(key=lambda c: c.get("last_seen", ""), reverse=True)

    start = (page - 1) * page_size
    return items[start : start + page_size]


@router.get("/{campaign_id}", response_model=CampaignResponse)
async def get_campaign_detail(campaign_id: str):
    """Campaign detail with IOC mapping."""
    validate_id(campaign_id)
    store = get_store()
    if campaign_id not in store.campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return store.campaigns[campaign_id]
