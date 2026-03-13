"""Ticketing client – escalation case creation."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from phishing_defense_agent.config import get_settings

logger = structlog.get_logger(__name__)


def create_ticket(verdict: dict[str, Any]) -> str | None:
    """Create an escalation ticket for a phishing incident."""
    settings = get_settings()
    if not settings.ticketing_api_key:
        logger.warning("ticketing_skipped", reason="no API key configured")
        return None

    url = f"{settings.ticketing_base_url}/tickets"
    headers = {"Authorization": f"Bearer {settings.ticketing_api_key}"}

    payload = {
        "title": (
            f"[Phishing] {verdict.get('verdict', 'suspicious').upper()} – "
            f"{verdict.get('subject', 'No subject')[:100]}"
        ),
        "description": verdict.get("explanation", ""),
        "priority": "P1" if verdict.get("action") == "block" else "P2",
        "source": "phishing-defense-agent",
        "message_id": verdict.get("message_id"),
        "sender": verdict.get("sender_address"),
        "risk_score": verdict.get("risk_score"),
    }

    with httpx.Client(timeout=10) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        ticket_id = resp.json().get("ticket_id")

    logger.info("ticket_created", message_id=verdict.get("message_id"), ticket_id=ticket_id)
    return ticket_id
