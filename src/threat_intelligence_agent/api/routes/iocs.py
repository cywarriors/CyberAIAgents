"""IOC endpoints — CRUD, relationships, export, feedback."""

from __future__ import annotations

import csv
import io
import json
import math
import re
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from threat_intelligence_agent.api.dependencies import get_store
from threat_intelligence_agent.api.schemas import (
    FeedbackRequest,
    IOCExportRequest,
    IOCLifecycleUpdate,
    IOCListResponse,
    IOCRelationshipResponse,
    IOCResponse,
)

router = APIRouter(prefix="/api/v1/iocs", tags=["iocs"])

_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def _validate(ioc_id: str) -> str:
    if not _ID_RE.match(ioc_id):
        raise HTTPException(422, "Invalid IOC identifier")
    return ioc_id


def _to_response(ioc: dict[str, Any]) -> IOCResponse:
    return IOCResponse(**{k: ioc.get(k, v.default) for k, v in IOCResponse.model_fields.items()})


@router.get("", response_model=IOCListResponse)
async def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    ioc_type: Optional[str] = None,
    lifecycle: Optional[str] = None,
    min_confidence: Optional[float] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
) -> IOCListResponse:
    store = get_store()
    items = list(store.iocs)

    if ioc_type:
        items = [i for i in items if i.get("ioc_type") == ioc_type]
    if lifecycle:
        items = [i for i in items if i.get("lifecycle") == lifecycle]
    if min_confidence is not None:
        items = [i for i in items if i.get("confidence", 0) >= min_confidence]
    if source:
        items = [i for i in items if source in i.get("sources", [])]
    if search:
        q = search.lower()
        items = [i for i in items if q in i.get("value", "").lower() or q in i.get("actor", "").lower()]

    total = len(items)
    pages = max(math.ceil(total / page_size), 1)
    start = (page - 1) * page_size
    paged = items[start : start + page_size]

    return IOCListResponse(
        items=[_to_response(i) for i in paged],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(ioc_id: str) -> IOCResponse:
    _validate(ioc_id)
    store = get_store()
    for ioc in store.iocs:
        if ioc.get("ioc_id") == ioc_id:
            return _to_response(ioc)
    raise HTTPException(404, "IOC not found")


@router.put("/{ioc_id}", response_model=IOCResponse)
async def update_ioc_lifecycle(ioc_id: str, body: IOCLifecycleUpdate) -> IOCResponse:
    _validate(ioc_id)
    store = get_store()
    for ioc in store.iocs:
        if ioc.get("ioc_id") == ioc_id:
            ioc["lifecycle"] = body.lifecycle
            store.audit_log.append({"action": "lifecycle_update", "ioc_id": ioc_id, "lifecycle": body.lifecycle, "reason": body.reason})
            return _to_response(ioc)
    raise HTTPException(404, "IOC not found")


@router.get("/{ioc_id}/relationships", response_model=IOCRelationshipResponse)
async def get_ioc_relationships(ioc_id: str) -> IOCRelationshipResponse:
    _validate(ioc_id)
    store = get_store()
    ioc = next((i for i in store.iocs if i.get("ioc_id") == ioc_id), None)
    if not ioc:
        raise HTTPException(404, "IOC not found")

    actor_name = ioc.get("actor", "")
    campaign_name = ioc.get("campaign", "")

    related_iocs = [
        {"ioc_id": i["ioc_id"], "value": i["value"], "relationship": "shared_source"}
        for i in store.iocs
        if i.get("ioc_id") != ioc_id and set(i.get("sources", [])) & set(ioc.get("sources", []))
    ][:10]

    related_actors = [
        {"actor_id": a["actor_id"], "name": a["name"]}
        for a in store.actors
        if actor_name and a["name"].lower() == actor_name.lower()
    ]

    related_campaigns = [
        {"campaign_id": c["campaign_id"], "name": c["name"]}
        for c in store.campaigns
        if campaign_name and c["campaign_id"] == campaign_name
    ]

    return IOCRelationshipResponse(ioc_id=ioc_id, related_iocs=related_iocs, related_actors=related_actors, related_campaigns=related_campaigns)


@router.post("/export")
async def export_iocs(body: IOCExportRequest):
    store = get_store()
    items = list(store.iocs)

    if body.ioc_ids:
        items = [i for i in items if i.get("ioc_id") in body.ioc_ids]

    if body.format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ioc_id", "ioc_type", "value", "confidence", "lifecycle", "sources", "tlp"])
        for i in items:
            writer.writerow([i.get("ioc_id"), i.get("ioc_type"), i.get("value"), i.get("confidence"), i.get("lifecycle"), ";".join(i.get("sources", [])), i.get("tlp")])
        return PlainTextResponse(output.getvalue(), media_type="text/csv")

    # Default: STIX 2.1
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--threat-intel-export",
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--{i.get('ioc_id', '')}",
                "pattern": f"[{_stix_pattern_type(i.get('ioc_type', ''))}:value = '{i.get('value', '')}']",
                "valid_from": i.get("first_seen", ""),
                "labels": i.get("labels", []),
                "confidence": int(i.get("confidence", 0)),
            }
            for i in items
        ],
    }
    return stix_bundle


@router.post("/{ioc_id}/feedback")
async def submit_feedback(ioc_id: str, body: FeedbackRequest):
    _validate(ioc_id)
    store = get_store()
    ioc = next((i for i in store.iocs if i.get("ioc_id") == ioc_id), None)
    if not ioc:
        raise HTTPException(404, "IOC not found")

    if body.action == "false_positive":
        ioc["lifecycle"] = "deprecated"
        ioc["confidence"] = max(ioc.get("confidence", 0) - 30, 0)
    elif body.action == "true_positive":
        ioc["lifecycle"] = "active"
        ioc["confidence"] = min(ioc.get("confidence", 0) + 10, 100)
    elif body.action in ("deprecate", "revoke"):
        ioc["lifecycle"] = body.action + "d"

    store.feedback.append({"ioc_id": ioc_id, "action": body.action, "analyst": body.analyst, "reason": body.reason})
    store.audit_log.append({"action": "feedback", "ioc_id": ioc_id, "feedback_action": body.action, "analyst": body.analyst})
    return {"status": "ok", "ioc_id": ioc_id, "action": body.action}


def _stix_pattern_type(ioc_type: str) -> str:
    mapping = {
        "ip": "ipv4-addr",
        "domain": "domain-name",
        "url": "url",
        "hash_md5": "file:hashes.MD5",
        "hash_sha1": "file:hashes.'SHA-1'",
        "hash_sha256": "file:hashes.'SHA-256'",
        "email": "email-addr",
    }
    return mapping.get(ioc_type, "artifact")
