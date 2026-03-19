"""Administration endpoints — health, config, statistics, audit log."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from threat_intelligence_agent.api.dependencies import get_store
from threat_intelligence_agent.config import get_settings

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/health")
async def admin_health() -> dict[str, Any]:
    return {"status": "healthy", "agent": "threat_intelligence_agent", "version": "1.0.0"}


@router.get("/config")
async def admin_config() -> dict[str, Any]:
    """Return non-sensitive configuration values."""
    s = get_settings()
    return {
        "agent_env": s.agent_env,
        "kafka_topic": s.kafka_topic,
        "org_industry": s.org_industry,
        "org_region": s.org_region,
        "confidence_distribution_threshold": s.confidence_distribution_threshold,
        "ioc_max_age_days": s.ioc_max_age_days,
        "api_port": s.api_port,
        "health_port": s.health_port,
        # Sensitive fields (API keys) intentionally excluded
    }


@router.get("/statistics")
async def admin_statistics() -> dict[str, Any]:
    store = get_store()
    return {
        "total_iocs": len(store.iocs),
        "active_iocs": sum(1 for i in store.iocs if i.get("lifecycle") == "active"),
        "deprecated_iocs": sum(1 for i in store.iocs if i.get("lifecycle") == "deprecated"),
        "revoked_iocs": sum(1 for i in store.iocs if i.get("lifecycle") == "revoked"),
        "total_briefs": len(store.briefs),
        "total_actors": len(store.actors),
        "total_feeds": len(store.feeds),
        "total_campaigns": len(store.campaigns),
        "total_feedback": len(store.feedback),
    }


@router.get("/audit-log")
async def admin_audit_log() -> list[dict[str, Any]]:
    store = get_store()
    return store.audit_log[-100:]  # Return last 100 entries
