"""Ticketing integration – create incident tickets from alerts."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from threat_detection_agent.config import get_settings

logger = structlog.get_logger(__name__)


def create_ticket(alert: dict[str, Any]) -> str | None:
    """Create a ticket in ServiceNow / Jira for the given alert. Returns ticket ID."""
    settings = get_settings()
    if not settings.ticketing_api_key:
        logger.warning("ticketing_skipped", reason="no API key configured")
        return None

    url = f"{settings.ticketing_base_url}/tickets"
    headers = {"Authorization": f"Bearer {settings.ticketing_api_key}"}
    payload = {
        "title": f"[{alert.get('severity')}] {alert.get('description', '')[:120]}",
        "description": alert.get("description", ""),
        "severity": alert.get("severity", "Medium"),
        "source": "threat-detection-agent",
        "alert_id": alert.get("alert_id"),
        "mitre_ids": alert.get("mitre_technique_ids", []),
    }
    with httpx.Client(timeout=10) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        ticket_id = resp.json().get("ticket_id")
    logger.info("ticket_created", alert_id=alert.get("alert_id"), ticket_id=ticket_id)
    return ticket_id
