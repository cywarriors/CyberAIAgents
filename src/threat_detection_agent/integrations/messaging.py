"""Messaging integration – send SOC notifications via webhook."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from threat_detection_agent.config import get_settings

logger = structlog.get_logger(__name__)


def send_soc_notification(alert: dict[str, Any]) -> None:
    """Send a high-severity alert notification to Teams / Slack via webhook."""
    settings = get_settings()
    if not settings.messaging_webhook_url:
        logger.warning("messaging_skipped", reason="no webhook URL configured")
        return

    techniques = ", ".join(alert.get("mitre_technique_ids", []))
    payload = {
        "text": (
            f"🚨 **{alert.get('severity')}** alert – {alert.get('description', '')[:200]}\n"
            f"MITRE: {techniques}\n"
            f"Alert ID: {alert.get('alert_id')}"
        ),
    }
    with httpx.Client(timeout=10) as client:
        resp = client.post(settings.messaging_webhook_url, json=payload)
        resp.raise_for_status()
    logger.info("soc_notification_sent", alert_id=alert.get("alert_id"))
