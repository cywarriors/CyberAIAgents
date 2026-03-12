"""Messaging integration – SOC notifications via Teams/Slack (P1/P2)."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)


def send_soc_notification(incident: dict[str, Any]) -> None:
    """Send triaged incident notification to Teams/Slack via webhook."""
    settings = get_settings()
    if not settings.messaging_webhook_url:
        logger.warning("messaging_skipped", reason="no webhook URL configured")
        return

    techniques = ", ".join(incident.get("mitre_technique_ids", []))
    actions = "; ".join(
        a.get("title", "") for a in incident.get("recommended_actions", [])[:3]
    )
    payload = {
        "text": (
            f"🚨 **{incident.get('priority', 'P3')} – {incident.get('severity', 'Medium')}** "
            f"incident – {incident.get('classification', 'unknown')}\n"
            f"{incident.get('triage_summary', '')[:300]}\n"
            f"MITRE: {techniques}\n"
            f"Next actions: {actions}\n"
            f"Incident ID: {incident.get('incident_id')}"
        ),
    }

    with httpx.Client(timeout=10) as client:
        resp = client.post(settings.messaging_webhook_url, json=payload)
        resp.raise_for_status()

    logger.info("soc_notification_sent", incident_id=incident.get("incident_id"))
