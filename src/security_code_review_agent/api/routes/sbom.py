from __future__ import annotations
import re
from typing import Any
from fastapi import APIRouter, HTTPException
from security_code_review_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/sbom", tags=["sbom"])
_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@router.get("")
async def list_sboms() -> list[dict[str, Any]]:
    return get_data_store().get_sboms()


@router.get("/{sbom_id}")
async def get_sbom(sbom_id: str) -> dict[str, Any]:
    if not _ID_RE.match(sbom_id):
        raise HTTPException(status_code=422, detail="Invalid identifier format")
    for s in get_data_store().get_sboms():
        if s.get("sbom_id") == sbom_id:
            return s
    raise HTTPException(status_code=404, detail="SBOM not found")
