"""Audit packs endpoints."""
from __future__ import annotations
import re
from typing import Any
from fastapi import APIRouter, HTTPException
from compliance_audit_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/audit-packs", tags=["audit-packs"])
_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@router.get("")
async def list_audit_packs(framework: str = "") -> list[dict[str, Any]]:
    store = get_data_store()
    packs = store.get_audit_packs()
    if framework:
        packs = [p for p in packs if p.get("framework", "").upper() == framework.upper()]
    return packs


@router.get("/{pack_id}")
async def get_audit_pack(pack_id: str) -> dict[str, Any]:
    if not _ID_RE.match(pack_id):
        raise HTTPException(status_code=422, detail="Invalid identifier format")
    store = get_data_store()
    for p in store.get_audit_packs():
        if p.get("pack_id") == pack_id:
            return p
    raise HTTPException(status_code=404, detail="Audit pack not found")
