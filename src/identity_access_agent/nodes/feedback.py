"""FeedbackAndPolicyTuneNode – process analyst decisions, adjust thresholds (FR-10)."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def feedback_and_policy_tune(state: dict[str, Any]) -> dict[str, Any]:
    """Collect analyst adjudication outcomes and prepare model tuning data.

    Implements FR-10 and FR-12 (configurable thresholds per user group).
    """
    feedback_queue: list[dict] = state.get("feedback_queue", [])
    alerts: list[dict] = state.get("alerts", [])

    logger.info(
        "feedback_and_policy_tune",
        alerts_count=len(alerts),
        pending_feedback=len(feedback_queue),
    )

    # In production this node would:
    # 1. Persist alerts to PostgreSQL for historical analysis
    # 2. Process analyst feedback to adjust per-user-group sensitivity
    # 3. Update impossible-travel VPN allowlists
    # 4. Track TP/FP rates for model tuning
    # 5. Generate weekly entitlement risk report (FR-11)

    severity_counts: dict[str, int] = {}
    for a in alerts:
        sev = a.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    logger.info(
        "alert_statistics",
        total=len(alerts),
        **severity_counts,
    )

    return {"feedback_queue": feedback_queue}
