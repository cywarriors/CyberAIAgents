"""Engagement management endpoints – CRUD for VAPT engagements and RoE."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from vapt_agent.api.dependencies import get_store
from vapt_agent.api.schemas import (
    EngagementCreate,
    EngagementResponse,
    EngagementUpdate,
    MessageResponse,
    RoEPayload,
)

router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"])


@router.get("", response_model=list[EngagementResponse])
async def list_engagements():
    store = get_store()
    return list(store.engagements.values())


@router.post("", response_model=EngagementResponse, status_code=201)
async def create_engagement(payload: EngagementCreate):
    store = get_store()
    now = datetime.now(timezone.utc)
    eng_id = str(uuid.uuid4())
    eng = {
        "id": eng_id,
        "name": payload.name,
        "description": payload.description,
        "status": "draft",
        "roe": payload.roe.model_dump(),
        "created_at": now,
        "updated_at": now,
        "findings_count": 0,
        "critical_count": 0,
        "high_count": 0,
    }
    store.engagements[eng_id] = eng
    return eng


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(engagement_id: str):
    store = get_store()
    eng = store.engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    return eng


@router.put("/{engagement_id}", response_model=EngagementResponse)
async def update_engagement(engagement_id: str, payload: EngagementUpdate):
    store = get_store()
    eng = store.engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    updates = payload.model_dump(exclude_none=True)
    if "roe" in updates:
        updates["roe"] = payload.roe.model_dump()
    eng.update(updates)
    eng["updated_at"] = datetime.now(timezone.utc)
    return eng


@router.delete("/{engagement_id}", response_model=MessageResponse)
async def delete_engagement(engagement_id: str):
    store = get_store()
    if engagement_id not in store.engagements:
        raise HTTPException(404, "Engagement not found")
    del store.engagements[engagement_id]
    return {"message": "Engagement deleted", "id": engagement_id}


@router.get("/{engagement_id}/roe", response_model=RoEPayload)
async def get_roe(engagement_id: str):
    store = get_store()
    eng = store.engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    return eng["roe"]


@router.put("/{engagement_id}/roe", response_model=RoEPayload)
async def update_roe(engagement_id: str, payload: RoEPayload):
    store = get_store()
    eng = store.engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    eng["roe"] = payload.model_dump()
    eng["updated_at"] = datetime.now(timezone.utc)
    return eng["roe"]
