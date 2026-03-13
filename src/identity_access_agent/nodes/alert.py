"""OpenCaseOrTicketNode – create SOC alerts and ITSM tickets (FR-07/09)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def open_case_or_ticket(state: dict[str, Any]) -> dict[str, Any]:
    """Generate SOC alerts and ITSM tickets for actionable risk.

    Implements FR-07 (case creation) and contributes to FR-09 (correlation context).
    """
    risk_scores: list[dict] = state.get("risk_scores", [])
    recommendations: list[dict] = state.get("recommendations", [])

    rec_by_user = {r["user_id"]: r for r in recommendations}

    logger.info("open_case_or_ticket", risk_count=len(risk_scores))

    alerts: list[dict[str, Any]] = []
    for scored in risk_scores:
        risk_level = scored.get("risk_level", "low")
        if risk_level in ("low",):
            continue  # no alert for low risk

        user_id = scored["user_id"]
        username = scored.get("username", "")
        risk_score = scored.get("risk_score", 0.0)
        rec = rec_by_user.get(user_id, {})

        severity = risk_level
        if risk_level == "critical":
            title = f"CRITICAL: Account takeover suspected – {username}"
        elif risk_level == "high":
            title = f"HIGH: Identity risk elevated – {username}"
        else:
            title = f"MEDIUM: Identity anomaly detected – {username}"

        indicators = scored.get("indicators", [])
        indicator_summary = "; ".join(
            f"{i.get('type', '?')}: {i.get('evidence', '')[:80]}"
            for i in indicators[:5]
        )

        alert: dict[str, Any] = {
            "alert_id": f"iam-alert-{uuid.uuid4().hex[:12]}",
            "user_id": user_id,
            "username": username,
            "severity": severity,
            "title": title,
            "description": (
                f"Identity risk score: {risk_score:.1f}/100 ({risk_level}). "
                f"Indicators: {indicator_summary or 'none'}. "
                f"Recommended control: {rec.get('control', 'none')}."
            ),
            "risk_score": risk_score,
            "indicators": indicators,
            "recommended_control": rec.get("control", "no_action"),
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "ticket_id": f"IAM-{uuid.uuid4().hex[:8].upper()}",
        }
        alerts.append(alert)

    logger.info("alerts_created", count=len(alerts))
    return {"alerts": alerts}
