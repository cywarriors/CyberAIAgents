"""User awareness dashboard endpoints (GUI-06)."""

from __future__ import annotations

from fastapi import APIRouter

from phishing_defense_agent.api.dependencies import get_store
from phishing_defense_agent.api.schemas import AwarenessMetricsResponse

router = APIRouter(prefix="/api/v1/awareness", tags=["awareness"])


@router.get("/metrics", response_model=AwarenessMetricsResponse)
async def get_awareness_metrics():
    """User awareness dashboard data."""
    store = get_store()
    reported = list(store.reported.values())
    feedback = store.feedback

    total_reports = len(reported)
    tp = sum(1 for r in reported if r.get("analyst_verdict") == "true_positive")
    fp = sum(1 for r in reported if r.get("analyst_verdict") == "false_positive")

    # Reporter leaderboard
    reporter_counts: dict[str, int] = {}
    for r in reported:
        email = r.get("reporter_email", "")
        if email:
            reporter_counts[email] = reporter_counts.get(email, 0) + 1

    top_reporters = sorted(
        [{"email": e, "count": c} for e, c in reporter_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    total_verdicts = len(store.verdicts)
    report_rate = total_reports / total_verdicts if total_verdicts else 0.0

    return AwarenessMetricsResponse(
        total_reports=total_reports,
        true_positive_reports=tp,
        false_positive_reports=fp,
        click_through_rate=0.0,
        report_rate=round(report_rate, 4),
        top_reporters=top_reporters,
        department_stats=[],
        training_completion_rate=0.0,
    )
