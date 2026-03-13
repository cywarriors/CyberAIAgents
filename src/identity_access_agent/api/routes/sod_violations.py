"""SoD violation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query

from identity_access_agent.api.dependencies import get_store
from identity_access_agent.api.schemas import SoDViolationResponse

router = APIRouter(prefix="/api/v1/sod-violations", tags=["sod-violations"])


@router.get("", response_model=list[SoDViolationResponse])
async def list_sod_violations(
    severity: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List segregation-of-duties violations."""
    store = get_store()
    items = list(store.sod_violations.values())
    if severity:
        items = [v for v in items if v.get("severity") == severity]
    items.sort(key=lambda x: x.get("severity", ""), reverse=True)
    return items[offset : offset + limit]
