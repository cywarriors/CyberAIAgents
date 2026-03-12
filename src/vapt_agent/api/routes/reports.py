"""Report generation and retrieval endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from vapt_agent.api.dependencies import get_store
from vapt_agent.api.schemas import MessageResponse, ReportCreate, ReportResponse

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("", response_model=list[ReportResponse])
async def list_reports(engagement_id: str | None = Query(None)):
    store = get_store()
    reports = list(store.reports.values())
    if engagement_id:
        reports = [r for r in reports if r["engagement_id"] == engagement_id]
    return sorted(reports, key=lambda r: r.get("generated_at", ""), reverse=True)


@router.post("", response_model=ReportResponse, status_code=201)
async def create_report(payload: ReportCreate):
    store = get_store()
    if payload.engagement_id not in store.engagements:
        raise HTTPException(404, "Engagement not found")

    report_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    record = {
        "id": report_id,
        "engagement_id": payload.engagement_id,
        "report_type": payload.report_type,
        "status": "completed",
        "generated_at": now,
        "download_url": f"/api/v1/reports/{report_id}/download",
        "content": None,
    }
    store.reports[report_id] = record
    return record


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: str):
    store = get_store()
    report = store.reports.get(report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    return report


@router.delete("/{report_id}", response_model=MessageResponse)
async def delete_report(report_id: str):
    store = get_store()
    if report_id not in store.reports:
        raise HTTPException(404, "Report not found")
    del store.reports[report_id]
    return {"message": "Report deleted"}
