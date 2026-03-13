"""Dashboard summary endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from phishing_defense_agent.api.dependencies import get_store
from phishing_defense_agent.api.schemas import DashboardSummaryResponse

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary():
    """Aggregated phishing defense metrics (GUI-01)."""
    store = get_store()
    verdicts = list(store.verdicts.values())
    quarantine = list(store.quarantine.values())
    campaigns = list(store.campaigns.values())

    verdict_counts: dict[str, int] = {}
    action_counts: dict[str, int] = {}
    dept_counts: dict[str, int] = {}

    for v in verdicts:
        vtype = v.get("verdict", "clean")
        verdict_counts[vtype] = verdict_counts.get(vtype, 0) + 1
        action = v.get("action", "allow")
        action_counts[action] = action_counts.get(action, 0) + 1
        for r in v.get("recipient_addresses", []):
            dept = r.split("@")[0] if "@" in r else "unknown"
            dept_counts[dept] = dept_counts.get(dept, 0) + 1

    total = len(verdicts)
    malicious = verdict_counts.get("malicious", 0)
    detection_rate = malicious / total if total else 0.0

    # FP rate from feedback
    fp_count = sum(1 for f in store.feedback if f.get("verdict") == "false_positive")
    fp_rate = fp_count / total if total else 0.0

    top_depts = sorted(
        [{"department": d, "count": c} for d, c in dept_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    return DashboardSummaryResponse(
        total_processed=total,
        clean_count=verdict_counts.get("clean", 0),
        suspicious_count=verdict_counts.get("suspicious", 0),
        malicious_count=malicious,
        quarantine_count=action_counts.get("quarantine", 0),
        blocked_count=action_counts.get("block", 0),
        warned_count=action_counts.get("warn", 0),
        allowed_count=action_counts.get("allow", 0),
        false_positive_rate=round(fp_rate, 4),
        detection_rate=round(detection_rate, 4),
        mean_verdict_latency_ms=0.0,
        active_campaigns=len(campaigns),
        iocs_extracted=sum(len(v.get("iocs", [])) for v in verdicts),
        user_reports_today=len(store.reported),
        top_targeted_departments=top_depts,
        verdict_trend=[],
    )
