"""Admin endpoints – health, config, audit."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query

from identity_access_agent.api.dependencies import get_store
from identity_access_agent.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/health")
async def health():
    """Agent health check."""
    store = get_store()
    return {
        "status": "healthy",
        "uptime_seconds": round(store.uptime, 1),
        "risk_scores_in_store": len(store.risk_scores),
        "alerts_in_store": len(store.alerts),
        "users_tracked": len(store.users),
        "sod_violations": len(store.sod_violations),
    }


@router.get("/config")
async def get_config():
    """Non-sensitive configuration summary."""
    settings = get_settings()
    return {
        "agent_env": settings.agent_env,
        "risk_threshold_critical": settings.risk_threshold_critical,
        "risk_threshold_high": settings.risk_threshold_high,
        "risk_threshold_medium": settings.risk_threshold_medium,
        "weight_session_anomaly": settings.weight_session_anomaly,
        "weight_auth_failure": settings.weight_auth_failure,
        "weight_privilege_change": settings.weight_privilege_change,
        "weight_takeover_signals": settings.weight_takeover_signals,
        "weight_context_enrichment": settings.weight_context_enrichment,
    }


@router.get("/statistics")
async def get_statistics():
    """Aggregate system statistics."""
    store = get_store()
    scores = list(store.risk_scores.values())

    level_dist: dict[str, int] = {}
    for s in scores:
        level = s.get("risk_level", "low")
        level_dist[level] = level_dist.get(level, 0) + 1

    severity_dist: dict[str, int] = {}
    for a in store.alerts.values():
        sev = a.get("severity", "medium")
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    return {
        "total_risk_scores": len(scores),
        "risk_level_distribution": level_dist,
        "total_alerts": len(store.alerts),
        "alert_severity_distribution": severity_dist,
        "sod_violations": len(store.sod_violations),
        "users_tracked": len(store.users),
        "feedback_count": len(store.feedback),
    }


@router.get("/audit-log")
async def get_audit_log(limit: int = Query(default=50, ge=1, le=500)):
    """Recent analyst feedback audit trail."""
    store = get_store()
    entries = sorted(store.feedback, key=lambda x: x.get("timestamp", ""), reverse=True)
    return entries[:limit]
