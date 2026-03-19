"""Admin endpoints – health, config, statistics."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter
from compliance_audit_agent.config import get_settings

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/health")
async def admin_health() -> dict[str, Any]:
    return {"status": "healthy", "agent": "compliance_audit_agent", "version": "1.0.0"}


@router.get("/config")
async def admin_config() -> dict[str, Any]:
    s = get_settings()
    return {
        "agent_env": s.agent_env,
        "kafka_topic": s.kafka_topic,
        "enabled_frameworks": s.enabled_frameworks,
        "org_unit": s.org_unit,
        "api_port": s.api_port,
        # API keys intentionally excluded
    }


@router.get("/statistics")
async def admin_statistics() -> dict[str, Any]:
    from compliance_audit_agent.api.store import get_data_store
    store = get_data_store()
    return {
        "evidence_count": len(store.get_evidence()),
        "audit_packs": len(store.get_audit_packs()),
        "gaps": len(store.get_gaps()),
        "framework_scores": store.get_framework_scores(),
    }
