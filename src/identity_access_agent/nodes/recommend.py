"""RecommendControlNode – suggest step-up MFA, session kill, or lockout (FR-06)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from identity_access_agent.config import get_settings

logger = structlog.get_logger(__name__)


def recommend_controls(state: dict[str, Any]) -> dict[str, Any]:
    """Map risk levels to recommended identity controls.

    Implements FR-06 and FR-08 (least-privilege suggestions).
    """
    risk_scores: list[dict] = state.get("risk_scores", [])
    sod_violations: list[dict] = state.get("sod_violations", [])
    settings = get_settings()

    logger.info("recommend_controls", users=len(risk_scores))

    recommendations: list[dict[str, Any]] = []
    for scored in risk_scores:
        user_id = scored["user_id"]
        username = scored.get("username", "")
        risk_level = scored.get("risk_level", "low")
        risk_score = scored.get("risk_score", 0.0)

        if risk_level == "critical":
            control = "session_kill"
            reason = "Critical identity risk – immediate session termination recommended"
            auto_enforce = False
            requires_approval = True
        elif risk_level == "high":
            control = "step_up_mfa"
            reason = "High identity risk – enforce step-up MFA challenge"
            auto_enforce = True
            requires_approval = False
        elif risk_level == "medium":
            control = "monitor"
            reason = "Medium identity risk – enhanced monitoring recommended"
            auto_enforce = False
            requires_approval = False
        else:
            control = "no_action"
            reason = "Low identity risk – no immediate action"
            auto_enforce = False
            requires_approval = False

        recommendations.append({
            "user_id": user_id,
            "username": username,
            "control": control,
            "reason": reason,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "auto_enforce": auto_enforce,
            "requires_approval": requires_approval,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # Least-privilege suggestions from SoD violations (FR-08)
    for sod in sod_violations:
        user_id = sod.get("user_id", "")
        # Don't duplicate if already in recommendations
        existing = next((r for r in recommendations if r["user_id"] == user_id), None)
        if existing and existing.get("control") in ("session_kill", "step_up_mfa"):
            continue
        recommendations.append({
            "user_id": user_id,
            "username": sod.get("username", ""),
            "control": "access_review",
            "reason": f"SoD violation: {sod.get('rule_name', '')}. {sod.get('recommendation', '')}",
            "risk_score": 0.0,
            "risk_level": "medium",
            "auto_enforce": False,
            "requires_approval": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    logger.info("recommendations_generated", count=len(recommendations))
    return {"recommendations": recommendations}
