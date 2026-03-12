"""Compliance schedule management endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from vapt_agent.api.dependencies import get_store
from vapt_agent.api.schemas import (
    ComplianceScheduleCreate,
    ComplianceScheduleResponse,
    MessageResponse,
)

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])


@router.get("/schedules", response_model=list[ComplianceScheduleResponse])
async def list_schedules():
    store = get_store()
    return list(store.compliance_schedules.values())


@router.post("/schedules", response_model=ComplianceScheduleResponse, status_code=201)
async def create_schedule(payload: ComplianceScheduleCreate):
    store = get_store()
    if payload.engagement_id not in store.engagements:
        raise HTTPException(404, "Engagement not found")
    sched_id = str(uuid.uuid4())
    record = {
        "id": sched_id,
        "engagement_id": payload.engagement_id,
        "framework": payload.framework,
        "frequency": payload.frequency,
        "next_due": payload.next_due,
        "last_completed": None,
        "status": "on_track",
    }
    store.compliance_schedules[sched_id] = record
    return record


@router.get("/schedules/{schedule_id}", response_model=ComplianceScheduleResponse)
async def get_schedule(schedule_id: str):
    store = get_store()
    sched = store.compliance_schedules.get(schedule_id)
    if not sched:
        raise HTTPException(404, "Schedule not found")
    return sched


@router.put("/schedules/{schedule_id}", response_model=ComplianceScheduleResponse)
async def update_schedule(schedule_id: str, payload: ComplianceScheduleCreate):
    store = get_store()
    sched = store.compliance_schedules.get(schedule_id)
    if not sched:
        raise HTTPException(404, "Schedule not found")
    sched["framework"] = payload.framework
    sched["frequency"] = payload.frequency
    sched["engagement_id"] = payload.engagement_id
    if payload.next_due:
        sched["next_due"] = payload.next_due
    return sched


@router.delete("/schedules/{schedule_id}", response_model=MessageResponse)
async def delete_schedule(schedule_id: str):
    store = get_store()
    if schedule_id not in store.compliance_schedules:
        raise HTTPException(404, "Schedule not found")
    del store.compliance_schedules[schedule_id]
    return {"message": "Schedule deleted"}
