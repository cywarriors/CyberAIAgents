"""Scan execution endpoints – create, status, stream."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from vapt_agent.api.dependencies import get_store
from vapt_agent.api.schemas import MessageResponse, ScanCreate, ScanResponse

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.get("", response_model=list[ScanResponse])
async def list_scans(engagement_id: str | None = None):
    store = get_store()
    items = list(store.scans.values())
    if engagement_id:
        items = [s for s in items if s.get("engagement_id") == engagement_id]
    return items


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(payload: ScanCreate):
    store = get_store()
    if payload.engagement_id not in store.engagements:
        raise HTTPException(404, "Engagement not found")

    scan_id = str(uuid.uuid4())
    scan = {
        "id": scan_id,
        "engagement_id": payload.engagement_id,
        "status": "running",
        "progress": 0.0,
        "targets": payload.targets,
        "engines": payload.engines,
        "findings_count": 0,
        "started_at": datetime.now(timezone.utc),
        "completed_at": None,
    }
    store.scans[scan_id] = scan

    # Update engagement status
    eng = store.engagements[payload.engagement_id]
    eng["status"] = "in_progress"
    eng["updated_at"] = datetime.now(timezone.utc)

    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    store = get_store()
    scan = store.scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("/{scan_id}/abort", response_model=MessageResponse)
async def abort_scan(scan_id: str):
    store = get_store()
    scan = store.scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    scan["status"] = "aborted"
    scan["completed_at"] = datetime.now(timezone.utc)
    return {"message": "Scan aborted", "id": scan_id}
