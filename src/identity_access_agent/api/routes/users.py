"""User risk profile endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from identity_access_agent.api.dependencies import get_store
from identity_access_agent.api.schemas import UserRiskResponse

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("", response_model=list[UserRiskResponse])
async def list_users(
    risk_level: str | None = None,
    department: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List monitored users with risk summary."""
    store = get_store()
    items = list(store.users.values())
    if risk_level:
        items = [u for u in items if u.get("risk_level") == risk_level]
    if department:
        items = [u for u in items if u.get("department") == department]
    items.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return items[offset : offset + limit]


@router.get("/{user_id}", response_model=UserRiskResponse)
async def get_user(user_id: str):
    """Retrieve risk profile for a specific user."""
    store = get_store()
    user = store.users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
