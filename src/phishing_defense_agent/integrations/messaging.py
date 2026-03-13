"""Messaging client – Slack / Teams webhook notifications."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from phishing_defense_agent.config import get_settings

logger = structlog.get_logger(__name__)


def send_soc_notification(verdict: dict[str, Any]) -> None:
    """Send phishing verdict notification to SOC via webhook."""
    settings = get_settings()
    if not settings.messaging_webhook_url:
        logger.warning("messaging_skipped", reason="no webhook URL configured")
        return

    action = verdict.get("action", "allow")
    emoji = {"block": "\U0001f6d1", "quarantine": "\u26a0\ufe0f", "warn": "\U0001f514"}.get(
        action, "\u2705"
    )

    payload = {
        "text": (
            f"{emoji} **Phishing {action.upper()}** – "
            f"Score: {verdict.get('risk_score', 0):.0f}/100\n"
            f"Subject: {verdict.get('subject', '')[:100]}\n"
            f"From: {verdict.get('sender_address', 'unknown')}\n"
            f"To: {', '.join(verdict.get('recipient_addresses', []))}\n"
            f"Message ID: {verdict.get('message_id')}"
        ),
    }

    with httpx.Client(timeout=10) as client:
        resp = client.post(settings.messaging_webhook_url, json=payload)
        resp.raise_for_status()

    logger.info("soc_notification_sent", message_id=verdict.get("message_id"))
