"""Evidence endpoints."""
from __future__ import annotations
import re
from typing import Any
from fastapi import APIRouter, HTTPException
from compliance_audit_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/evidence", tags=["evidence"])
_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@router.get("")
async def list_evidence(page: int = 1, page_size: int = 20, framework: str = "") -> dict[str, Any]:
    page_size = min(max(page_size, 1), 100)
    store = get_data_store()
    items = store.get_evidence()
    if framework:
        items = [i for i in items if i.get("framework", "").upper() == framework.upper()]
    start = (page - 1) * page_size
    return {"items": items[start: start + page_size], "total": len(items)}


@router.get("/{evidence_id}")
async def get_evidence(evidence_id: str) -> dict[str, Any]:
    if not _ID_RE.match(evidence_id):
        raise HTTPException(status_code=422, detail="Invalid identifier format")
    store = get_data_store()
    for ev in store.get_evidence():
        if ev.get("evidence_id") == evidence_id:
            return ev
    raise HTTPException(status_code=404, detail="Evidence not found")
