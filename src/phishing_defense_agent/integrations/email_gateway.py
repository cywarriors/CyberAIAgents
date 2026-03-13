"""Email gateway client – mail inspection and quarantine actions."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from phishing_defense_agent.config import get_settings

logger = structlog.get_logger(__name__)


def fetch_inbound_emails(limit: int = 100) -> list[dict[str, Any]]:
    """Pull recent inbound emails from the mail gateway API."""
    settings = get_settings()
    if not settings.email_gateway_api_key:
        logger.warning("email_gateway_fetch_skipped", reason="no API key configured")
        return []

    url = f"{settings.email_gateway_base_url}/messages/inbound"
    headers = {"Authorization": f"Bearer {settings.email_gateway_api_key}"}

    with httpx.Client(timeout=30) as client:
        resp = client.get(url, headers=headers, params={"limit": limit})
        resp.raise_for_status()
        return resp.json().get("messages", [])


def quarantine_email(message_id: str, reason: str) -> bool:
    """Move an email to quarantine via the gateway API."""
    settings = get_settings()
    if not settings.email_gateway_api_key:
        logger.warning("quarantine_skipped", reason="no API key configured")
        return False

    url = f"{settings.email_gateway_base_url}/messages/{message_id}/quarantine"
    headers = {"Authorization": f"Bearer {settings.email_gateway_api_key}"}

    with httpx.Client(timeout=10) as client:
        resp = client.post(url, headers=headers, json={"reason": reason})
        resp.raise_for_status()

    logger.info("email_quarantined_via_gateway", message_id=message_id)
    return True


def release_email(message_id: str, analyst_id: str, justification: str) -> bool:
    """Release a quarantined email."""
    settings = get_settings()
    if not settings.email_gateway_api_key:
        logger.warning("release_skipped", reason="no API key configured")
        return False

    url = f"{settings.email_gateway_base_url}/messages/{message_id}/release"
    headers = {"Authorization": f"Bearer {settings.email_gateway_api_key}"}

    with httpx.Client(timeout=10) as client:
        resp = client.post(
            url, headers=headers,
            json={"analyst_id": analyst_id, "justification": justification},
        )
        resp.raise_for_status()

    logger.info("email_released", message_id=message_id, analyst=analyst_id)
    return True


def block_sender(sender_domain: str, reason: str) -> bool:
    """Add sender domain to block list."""
    settings = get_settings()
    if not settings.email_gateway_api_key:
        logger.warning("block_skipped", reason="no API key configured")
        return False

    url = f"{settings.email_gateway_base_url}/blocklist/domains"
    headers = {"Authorization": f"Bearer {settings.email_gateway_api_key}"}

    with httpx.Client(timeout=10) as client:
        resp = client.post(url, headers=headers, json={"domain": sender_domain, "reason": reason})
        resp.raise_for_status()

    logger.info("sender_blocked", domain=sender_domain)
    return True
