"""Dashboard summary endpoint – aggregated metrics."""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter

from vapt_agent.api.dependencies import get_store
from vapt_agent.api.schemas import DashboardSummary

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary():
    store = get_store()

    findings = list(store.findings.values())
    severity_counts = Counter(f.get("severity", "info") for f in findings)

    engagements = list(store.engagements.values())
    active_engagements = sum(
        1 for e in engagements if e.get("status") == "in_progress"
    )

    return {
        "active_engagements": active_engagements,
        "total_findings": len(findings),
        "critical_findings": severity_counts.get("critical", 0),
        "high_findings": severity_counts.get("high", 0),
        "medium_findings": severity_counts.get("medium", 0),
        "low_findings": severity_counts.get("low", 0),
        "assets_discovered": 0,
        "attack_paths_found": len(store.attack_paths),
        "exploits_validated": len(store.exploits),
        "reports_generated": len(store.reports),
        "severity_breakdown": dict(severity_counts),
    }
