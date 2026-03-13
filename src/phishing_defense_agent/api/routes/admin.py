"""Admin endpoints – health, config, audit (GUI-08)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query

from phishing_defense_agent.api.dependencies import get_store
from phishing_defense_agent.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/health")
async def health():
    """Agent health check."""
    store = get_store()
    return {
        "status": "healthy",
        "uptime_seconds": round(store.uptime, 1),
        "verdicts_in_store": len(store.verdicts),
        "quarantine_size": len(store.quarantine),
        "campaigns_tracked": len(store.campaigns),
    }


@router.get("/config")
async def get_config():
    """Non-sensitive configuration summary."""
    settings = get_settings()
    return {
        "agent_env": settings.agent_env,
        "risk_threshold_block": settings.risk_threshold_block,
        "risk_threshold_quarantine": settings.risk_threshold_quarantine,
        "risk_threshold_warn": settings.risk_threshold_warn,
        "weight_sender_auth": settings.weight_sender_auth,
        "weight_content_analysis": settings.weight_content_analysis,
        "weight_url_reputation": settings.weight_url_reputation,
        "weight_attachment_risk": settings.weight_attachment_risk,
        "weight_threat_intel": settings.weight_threat_intel,
    }


@router.get("/statistics")
async def get_statistics():
    """Aggregate system statistics."""
    store = get_store()
    verdicts = list(store.verdicts.values())

    verdict_dist: dict[str, int] = {}
    action_dist: dict[str, int] = {}
    for v in verdicts:
        vtype = v.get("verdict", "clean")
        verdict_dist[vtype] = verdict_dist.get(vtype, 0) + 1
        action = v.get("action", "allow")
        action_dist[action] = action_dist.get(action, 0) + 1

    return {
        "total_verdicts": len(verdicts),
        "verdict_distribution": verdict_dist,
        "action_distribution": action_dist,
        "quarantine_size": len(store.quarantine),
        "campaigns_tracked": len(store.campaigns),
        "user_reports": len(store.reported),
        "feedback_items": len(store.feedback),
    }


@router.get("/audit-log")
async def get_audit_log(limit: int = Query(50, ge=1, le=500)):
    """Recent feedback and analyst actions."""
    store = get_store()
    items = list(store.feedback)
    items.sort(key=lambda x: x.get("submitted_at", ""), reverse=True)
    return items[:limit]
