"""Pipeline processing endpoint."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException

from identity_access_agent.api.dependencies import get_store
from identity_access_agent.api.schemas import ProcessEventsRequest
from identity_access_agent.graph import get_compiled_graph

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/process", tags=["processing"])


@router.post("")
async def process_events(body: ProcessEventsRequest):
    """Run identity risk pipeline on submitted events."""
    if not body.auth_events and not body.role_changes:
        raise HTTPException(status_code=400, detail="At least one event is required")

    try:
        graph = get_compiled_graph()
        result = graph.invoke({
            "raw_auth_events": body.auth_events,
            "raw_role_changes": body.role_changes,
        })

        _persist_results(result)

        risk_scores = result.get("risk_scores", [])
        alerts = result.get("alerts", [])
        return {
            "message": "Pipeline completed",
            "auth_events_processed": len(body.auth_events),
            "role_changes_processed": len(body.role_changes),
            "risk_scores_computed": len(risk_scores),
            "alerts_created": len(alerts),
            "sod_violations": len(result.get("sod_violations", [])),
            "recommendations": len(result.get("recommendations", [])),
        }
    except Exception:
        logger.exception("Pipeline execution failed")
        raise HTTPException(status_code=500, detail="Pipeline execution failed")


def _persist_results(result: dict[str, Any]) -> None:
    """Persist pipeline results to in-memory store."""
    store = get_store()
    now = datetime.now(timezone.utc).isoformat()

    for score in result.get("risk_scores", []):
        uid = score.get("user_id", "")
        store.risk_scores[uid] = score
        # Upsert user record
        user = store.users.get(uid, {})
        user.update({
            "user_id": uid,
            "username": score.get("username", ""),
            "risk_score": score.get("risk_score", 0),
            "risk_level": score.get("risk_level", "low"),
            "last_login": now,
        })
        store.users[uid] = user

    for alert in result.get("alerts", []):
        aid = alert.get("alert_id", "")
        store.alerts[aid] = alert
        # Track active alert count on user
        uid = alert.get("user_id", "")
        if uid in store.users:
            active = sum(
                1 for a in store.alerts.values()
                if a.get("user_id") == uid and a.get("status") == "open"
            )
            store.users[uid]["active_alerts"] = active

    for sod in result.get("sod_violations", []):
        key = f"{sod.get('user_id', '')}:{sod.get('rule_id', '')}"
        store.sod_violations[key] = sod
        uid = sod.get("user_id", "")
        if uid in store.users:
            store.users[uid]["sod_violations"] = sum(
                1 for s in store.sod_violations.values() if s.get("user_id") == uid
            )

    for rec in result.get("recommendations", []):
        uid = rec.get("user_id", "")
        store.recommendations[uid] = rec
