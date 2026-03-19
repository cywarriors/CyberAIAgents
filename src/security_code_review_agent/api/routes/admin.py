from __future__ import annotations
from typing import Any
from fastapi import APIRouter
from security_code_review_agent.api.store import get_data_store
from security_code_review_agent.config import get_settings

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "healthy", "service": "security-code-review-agent"}


@router.get("/config")
async def config() -> dict[str, Any]:
    s = get_settings()
    return {
        "vcs_platform": s.vcs_platform,
        "supported_languages": s.supported_languages,
        "policy_block_severity": s.policy_block_severity,
        "policy_warn_severity": s.policy_warn_severity,
        "agent_env": s.agent_env,
    }


@router.get("/statistics")
async def statistics() -> dict[str, Any]:
    store = get_data_store()
    return {
        "sast_findings_count": len(store.get_sast_findings()),
        "secrets_findings_count": len(store.get_secrets_findings()),
        "sca_findings_count": len(store.get_sca_findings()),
        "sbom_count": len(store.get_sboms()),
        "scan_count": len(store.get_scans()),
    }
