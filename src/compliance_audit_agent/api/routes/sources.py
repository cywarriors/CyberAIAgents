"""Evidence source (feed) management endpoints."""
from __future__ import annotations
import re
import uuid
from typing import Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from compliance_audit_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/sources", tags=["sources"])
_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class SourceCreate(BaseModel):
    name: str
    source_type: str          # siem, edr, iam, cloud
    api_url: str
    enabled: bool = True


@router.get("")
async def list_sources() -> list[dict[str, Any]]:
    return get_data_store().get_feeds()


@router.post("", status_code=201)
async def create_source(payload: SourceCreate) -> dict[str, Any]:
    feed = {
        "feed_id": str(uuid.uuid4()),
        "name": payload.name,
        "source_type": payload.source_type,
        "api_url": payload.api_url,
        "enabled": payload.enabled,
    }
    get_data_store().add_feed(feed)
    return feed


@router.delete("/{source_id}", status_code=204)
async def delete_source(source_id: str) -> None:
    if not _ID_RE.match(source_id):
        raise HTTPException(status_code=422, detail="Invalid identifier format")
    if not get_data_store().delete_feed(source_id):
        raise HTTPException(status_code=404, detail="Source not found")
