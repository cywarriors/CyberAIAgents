"""Ticketing / ITSM integration – create and update incident tickets (FR-08)."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)


def create_ticket(incident: dict[str, Any]) -> str | None:
    """Create a new ticket in ServiceNow/Jira with enriched incident data."""
    settings = get_settings()
    if not settings.ticketing_api_key:
        logger.warning("ticketing_skipped", reason="no API key configured")
        return None

    url = f"{settings.ticketing_base_url}/tickets"
    headers = {"Authorization": f"Bearer {settings.ticketing_api_key}"}
    payload = {
        "title": (
            f"[{incident.get('priority', 'P3')}] "
            f"[{incident.get('classification', 'unknown')}] "
            f"{incident.get('triage_summary', '')[:120]}"
        ),
        "description": incident.get("triage_summary", ""),
        "priority": incident.get("priority", "P3"),
        "classification": incident.get("classification", "unknown"),
        "severity": incident.get("severity", "Medium"),
        "source": "incident-triage-agent",
        "incident_id": incident.get("incident_id"),
        "alert_ids": incident.get("alert_ids", []),
        "mitre_ids": incident.get("mitre_technique_ids", []),
        "entity_profiles": incident.get("entity_profiles", []),
        "recommended_actions": incident.get("recommended_actions", []),
        "timeline": incident.get("timeline", []),
    }

    with httpx.Client(timeout=10) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        ticket_id = resp.json().get("ticket_id")

    logger.info(
        "ticket_created",
        incident_id=incident.get("incident_id"),
        ticket_id=ticket_id,
    )
    return ticket_id


def update_ticket(ticket_id: str, updates: dict[str, Any]) -> None:
    """Update an existing ticket with new enrichment data."""
    settings = get_settings()
    if not settings.ticketing_api_key:
        logger.warning("ticket_update_skipped", reason="no API key configured")
        return

    url = f"{settings.ticketing_base_url}/tickets/{ticket_id}"
    headers = {"Authorization": f"Bearer {settings.ticketing_api_key}"}

    with httpx.Client(timeout=10) as client:
        resp = client.patch(url, json=updates, headers=headers)
        resp.raise_for_status()

    logger.info("ticket_updated", ticket_id=ticket_id)
