"""Framework score endpoints."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, HTTPException
from compliance_audit_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/frameworks", tags=["frameworks"])


@router.get("")
async def list_frameworks() -> list[dict[str, Any]]:
    store = get_data_store()
    scores = store.get_framework_scores()
    return list(scores.values())


@router.get("/{framework_id}")
async def get_framework(framework_id: str) -> dict[str, Any]:
    store = get_data_store()
    scores = store.get_framework_scores()
    normalized = framework_id.upper()
    if normalized in scores:
        return scores[normalized]
    raise HTTPException(status_code=404, detail="Framework score not found")
