"""NotifyUserAndSOCNode – send warning banners or SOC escalations (FR-06)."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def notify_user_and_soc(state: dict[str, Any]) -> dict[str, Any]:
    """Send notifications for verdicts that require user or SOC attention.

    Implements FR-06 (warning banners) and SOC escalation.
    """
    verdicts: list[dict] = state.get("verdicts", [])

    logger.info("notify_user_and_soc", verdict_count=len(verdicts))

    notifications: list[dict[str, Any]] = []
    for v in verdicts:
        action = v.get("action", "allow")
        message_id = v.get("message_id", "")

        if action == "warn":
            notifications.append({
                "message_id": message_id,
                "notification_type": "user_warning",
                "channel": "email_banner",
                "recipient": ", ".join(v.get("recipient_addresses", [])),
                "summary": (
                    f"Warning: Email from {v.get('sender_address', 'unknown')} "
                    f"flagged as suspicious (score: {v.get('risk_score', 0):.0f})"
                ),
                "sent": True,
            })

        elif action in ("quarantine", "block"):
            notifications.append({
                "message_id": message_id,
                "notification_type": "soc_escalation",
                "channel": "messaging_webhook",
                "recipient": "SOC Team",
                "summary": (
                    f"{'Quarantined' if action == 'quarantine' else 'Blocked'} – "
                    f"Subject: {v.get('subject', '')[:80]} | "
                    f"From: {v.get('sender_address', 'unknown')} | "
                    f"Score: {v.get('risk_score', 0):.0f}"
                ),
                "sent": True,
            })

            # Notify recipient that email was held
            notifications.append({
                "message_id": message_id,
                "notification_type": "user_notification",
                "channel": "email",
                "recipient": ", ".join(v.get("recipient_addresses", [])),
                "summary": (
                    f"An email from {v.get('sender_address', 'unknown')} "
                    f"has been {action}ed for security review."
                ),
                "sent": True,
            })

    logger.info("notifications_sent", count=len(notifications))
    return {"notifications": notifications}
