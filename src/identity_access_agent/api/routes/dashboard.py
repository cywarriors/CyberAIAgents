"""Dashboard summary endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from identity_access_agent.api.dependencies import get_store
from identity_access_agent.api.schemas import DashboardSummaryResponse

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary():
    """Aggregated identity risk metrics."""
    store = get_store()
    scores = list(store.risk_scores.values())
    alerts = list(store.alerts.values())

    level_counts: dict[str, int] = {}
    signal_counts: dict[str, int] = {"impossible_travel": 0, "mfa_fatigue": 0, "brute_force": 0, "privilege_escalation": 0}
    total_score = 0.0

    for s in scores:
        level = s.get("risk_level", "low")
        level_counts[level] = level_counts.get(level, 0) + 1
        total_score += s.get("risk_score", 0.0)
        for ind in s.get("indicators", []):
            itype = ind.get("indicator_type", "")
            if itype in signal_counts:
                signal_counts[itype] += 1

    open_alerts = sum(1 for a in alerts if a.get("status") == "open")
    fp_count = sum(1 for f in store.feedback if f.get("verdict") == "false_positive")
    total = len(scores)
    fp_rate = fp_count / total if total else 0.0

    top_risky = sorted(scores, key=lambda x: x.get("risk_score", 0), reverse=True)[:10]
    top_risky_users = [
        {"user_id": u.get("user_id", ""), "username": u.get("username", ""), "risk_score": u.get("risk_score", 0)}
        for u in top_risky
    ]

    return DashboardSummaryResponse(
        total_events_processed=total,
        critical_risk_users=level_counts.get("critical", 0),
        high_risk_users=level_counts.get("high", 0),
        medium_risk_users=level_counts.get("medium", 0),
        low_risk_users=level_counts.get("low", 0),
        total_alerts=len(alerts),
        open_alerts=open_alerts,
        sod_violations=len(store.sod_violations),
        impossible_travel_detections=signal_counts["impossible_travel"],
        mfa_fatigue_detections=signal_counts["mfa_fatigue"],
        brute_force_detections=signal_counts["brute_force"],
        privilege_escalation_detections=signal_counts["privilege_escalation"],
        false_positive_rate=round(fp_rate, 4),
        mean_risk_score=round(total_score / total, 2) if total else 0.0,
        top_risky_users=top_risky_users,
        risk_trend=[],
    )
