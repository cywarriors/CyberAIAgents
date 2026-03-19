from __future__ import annotations
from typing import Any
from fastapi import APIRouter
from security_code_review_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/security")
async def security_dashboard() -> dict[str, Any]:
    store = get_data_store()
    sast = store.get_sast_findings()
    secrets = store.get_secrets_findings()
    sca = store.get_sca_findings()
    all_findings = sast + secrets + sca

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "total_findings": len(all_findings),
        "sast_findings": len(sast),
        "secrets_findings": len(secrets),
        "sca_findings": len(sca),
        "severity_breakdown": severity_counts,
    }
