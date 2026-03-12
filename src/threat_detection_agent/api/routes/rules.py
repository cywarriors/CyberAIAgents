"""Detection rule management endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from threat_detection_agent.api.dependencies import get_store
from threat_detection_agent.api.schemas import (
    MessageResponse,
    RuleCreate,
    RuleResponse,
    RuleTestRequest,
    RuleTestResult,
    RuleUpdate,
)

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


@router.get("", response_model=list[RuleResponse])
async def list_rules(status: str | None = None):
    store = get_store()
    items = list(store.rules.values())
    if status:
        items = [r for r in items if r.get("status") == status]
    items.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return [RuleResponse(**r) for r in items]


@router.post("", response_model=RuleResponse, status_code=201)
async def create_rule(payload: RuleCreate):
    store = get_store()
    rid = f"RULE-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    rule = {
        "rule_id": rid,
        **payload.model_dump(),
        "status": "draft",
        "created_at": now,
        "updated_at": now,
        "hit_count": 0,
    }
    store.rules[rid] = rule
    return RuleResponse(**rule)


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: str):
    store = get_store()
    rule = store.rules.get(rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return RuleResponse(**rule)


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: str, payload: RuleUpdate):
    store = get_store()
    rule = store.rules.get(rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    for k, v in payload.model_dump(exclude_none=True).items():
        rule[k] = v
    rule["updated_at"] = datetime.now(timezone.utc).isoformat()
    return RuleResponse(**rule)


@router.delete("/{rule_id}", response_model=MessageResponse)
async def delete_rule(rule_id: str):
    store = get_store()
    if rule_id not in store.rules:
        raise HTTPException(404, "Rule not found")
    del store.rules[rule_id]
    return MessageResponse(message="Rule deleted")


@router.post("/{rule_id}/test", response_model=RuleTestResult)
async def test_rule(rule_id: str, payload: RuleTestRequest):
    store = get_store()
    if rule_id not in store.rules:
        raise HTTPException(404, "Rule not found")
    # Simulate rule test – in production this would run the rule logic
    matched_ids = [
        e.get("event_id", f"evt-{i}")
        for i, e in enumerate(payload.test_events)
        if e.get("should_match", False)
    ]
    return RuleTestResult(
        rule_id=rule_id,
        events_tested=len(payload.test_events),
        matches_found=len(matched_ids),
        matched_event_ids=matched_ids,
    )
