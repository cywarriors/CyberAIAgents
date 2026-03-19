from __future__ import annotations
import re
from typing import Any
from fastapi import APIRouter, HTTPException
from security_code_review_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])
_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@router.get("")
async def list_findings(finding_type: str = "", severity: str = "") -> dict[str, Any]:
    store = get_data_store()
    all_findings: list[dict] = []
    if finding_type in ("", "sast"):
        all_findings += [{"type": "sast", **f} for f in store.get_sast_findings()]
    if finding_type in ("", "secret"):
        all_findings += [{"type": "secret", **f} for f in store.get_secrets_findings()]
    if finding_type in ("", "sca"):
        all_findings += [{"type": "sca", **f} for f in store.get_sca_findings()]
    if severity:
        all_findings = [f for f in all_findings if f.get("severity", "").lower() == severity.lower()]
    return {"items": all_findings, "total": len(all_findings)}


@router.get("/{finding_id}")
async def get_finding(finding_id: str) -> dict[str, Any]:
    if not _ID_RE.match(finding_id):
        raise HTTPException(status_code=422, detail="Invalid identifier format")
    store = get_data_store()
    for f in store.get_sast_findings() + store.get_secrets_findings() + store.get_sca_findings():
        if f.get("finding_id") == finding_id:
            return f
    raise HTTPException(status_code=404, detail="Finding not found")
