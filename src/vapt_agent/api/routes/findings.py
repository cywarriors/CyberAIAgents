"""Findings endpoints – paginated query, detail, status update."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from vapt_agent.api.dependencies import get_store
from vapt_agent.api.schemas import (
    FindingResponse,
    FindingUpdate,
    PaginatedFindings,
    SeverityLevel,
)

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


@router.get("", response_model=PaginatedFindings)
async def list_findings(
    engagement_id: str | None = None,
    severity: list[SeverityLevel] | None = Query(None),
    asset_id: str | None = None,
    cve_id: str | None = None,
    cwe_id: str | None = None,
    status: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    sort_by: str = "composite_score",
    sort_order: str = "desc",
):
    store = get_store()
    items = list(store.findings.values())

    # Filters
    if engagement_id:
        items = [f for f in items if f.get("engagement_id") == engagement_id]
    if severity:
        sev_values = {s.value for s in severity}
        items = [f for f in items if f.get("severity") in sev_values]
    if asset_id:
        items = [f for f in items if f.get("asset_id") == asset_id]
    if cve_id:
        items = [f for f in items if f.get("cve_id") == cve_id]
    if cwe_id:
        items = [f for f in items if f.get("cwe_id") == cwe_id]
    if status:
        items = [f for f in items if f.get("status") == status]
    if search:
        q = search.lower()
        items = [
            f for f in items
            if q in (f.get("title", "")).lower()
            or q in (f.get("cve_id") or "").lower()
            or q in (f.get("cwe_id") or "").lower()
        ]

    # Sort
    reverse = sort_order == "desc"
    items.sort(key=lambda f: f.get(sort_by, 0) or 0, reverse=reverse)

    total = len(items)
    pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    page_items = items[start: start + page_size]

    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str):
    store = get_store()
    finding = store.findings.get(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    return finding


@router.put("/{finding_id}", response_model=FindingResponse)
async def update_finding(finding_id: str, payload: FindingUpdate):
    store = get_store()
    finding = store.findings.get(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    updates = payload.model_dump(exclude_none=True)
    finding.update(updates)
    return finding
