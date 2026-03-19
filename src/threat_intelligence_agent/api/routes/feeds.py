"""Feed management endpoints — CRUD + health."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from threat_intelligence_agent.api.dependencies import get_store
from threat_intelligence_agent.api.schemas import (
    FeedCreateRequest,
    FeedHealthResponse,
    FeedSourceResponse,
    FeedUpdateRequest,
)

router = APIRouter(prefix="/api/v1/feeds", tags=["feeds"])

_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@router.get("")
async def list_feeds() -> list[FeedSourceResponse]:
    store = get_store()
    return [FeedSourceResponse(**f) for f in store.feeds]


@router.post("", response_model=FeedSourceResponse, status_code=201)
async def create_feed(body: FeedCreateRequest) -> FeedSourceResponse:
    store = get_store()
    feed = {
        "feed_id": f"feed-{uuid.uuid4().hex[:8]}",
        "name": body.name,
        "source_type": body.source_type,
        "url": body.url,
        "enabled": body.enabled,
        "last_poll": "",
        "success_rate": 1.0,
        "ioc_yield": 0,
        "quality_score": 50.0,
        "false_positive_rate": 0.0,
    }
    store.feeds.append(feed)
    store.audit_log.append({"action": "feed_created", "feed_id": feed["feed_id"], "timestamp": datetime.now(timezone.utc).isoformat()})
    return FeedSourceResponse(**feed)


@router.get("/{feed_id}", response_model=FeedSourceResponse)
async def get_feed(feed_id: str) -> FeedSourceResponse:
    if not _ID_RE.match(feed_id):
        raise HTTPException(422, "Invalid feed identifier")
    store = get_store()
    for f in store.feeds:
        if f.get("feed_id") == feed_id:
            return FeedSourceResponse(**f)
    raise HTTPException(404, "Feed not found")


@router.put("/{feed_id}", response_model=FeedSourceResponse)
async def update_feed(feed_id: str, body: FeedUpdateRequest) -> FeedSourceResponse:
    if not _ID_RE.match(feed_id):
        raise HTTPException(422, "Invalid feed identifier")
    store = get_store()
    for f in store.feeds:
        if f.get("feed_id") == feed_id:
            if body.name is not None:
                f["name"] = body.name
            if body.url is not None:
                f["url"] = body.url
            if body.enabled is not None:
                f["enabled"] = body.enabled
            store.audit_log.append({"action": "feed_updated", "feed_id": feed_id, "timestamp": datetime.now(timezone.utc).isoformat()})
            return FeedSourceResponse(**f)
    raise HTTPException(404, "Feed not found")


@router.delete("/{feed_id}", status_code=204)
async def delete_feed(feed_id: str):
    if not _ID_RE.match(feed_id):
        raise HTTPException(422, "Invalid feed identifier")
    store = get_store()
    for idx, f in enumerate(store.feeds):
        if f.get("feed_id") == feed_id:
            store.feeds.pop(idx)
            store.audit_log.append({"action": "feed_deleted", "feed_id": feed_id, "timestamp": datetime.now(timezone.utc).isoformat()})
            return
    raise HTTPException(404, "Feed not found")


@router.get("/{feed_id}/health", response_model=FeedHealthResponse)
async def get_feed_health(feed_id: str) -> FeedHealthResponse:
    if not _ID_RE.match(feed_id):
        raise HTTPException(422, "Invalid feed identifier")
    store = get_store()
    for f in store.feeds:
        if f.get("feed_id") == feed_id:
            status = "healthy" if f.get("success_rate", 0) >= 0.9 else "degraded"
            return FeedHealthResponse(
                feed_id=f["feed_id"],
                name=f["name"],
                status=status,
                last_poll=f.get("last_poll", ""),
                success_rate=f.get("success_rate", 0),
                ioc_yield=f.get("ioc_yield", 0),
            )
    raise HTTPException(404, "Feed not found")
