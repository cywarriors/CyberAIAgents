"""Messaging integration – post VAPT notifications to webhook/Slack/Teams."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from vapt_agent.config import get_settings

logger = structlog.get_logger(__name__)


def send_notification(message: dict[str, Any]) -> bool:
    """Post a notification to the configured messaging webhook."""
    settings = get_settings()
    if not settings.messaging_webhook_url:
        logger.warning("messaging_skipped", reason="no webhook URL configured")
        return False

    payload = {
        "text": message.get("text", ""),
        "severity": message.get("severity", "info"),
        "engagement_id": message.get("engagement_id"),
        "findings_count": message.get("findings_count", 0),
    }
    with httpx.Client(timeout=15) as client:
        resp = client.post(settings.messaging_webhook_url, json=payload)
        resp.raise_for_status()
        return True
