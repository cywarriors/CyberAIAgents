"""Integration: ITSM / Ticketing (ServiceNow / Jira) for intelligence requests."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _get_settings():
    from threat_intelligence_agent.config import get_settings
    return get_settings()


def create_intel_request_ticket(
    summary: str,
    description: str,
    priority: str = "Medium",
    labels: list[str] | None = None,
) -> dict[str, Any]:
    """Create an intelligence request ticket in the configured ITSM system.

    Returns a dict with ``ticket_id`` and ``status``.
    """
    settings = _get_settings()
    if not settings.ticketing_url or not settings.ticketing_api_key:
        logger.warning("ticketing.not_configured — returning mock ticket")
        import uuid

        return {"ticket_id": f"MOCK-{uuid.uuid4().hex[:6].upper()}", "status": "created"}

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{settings.ticketing_url}/rest/api/2/issue",
                headers={"Authorization": f"Bearer {settings.ticketing_api_key}"},
                json={
                    "fields": {
                        "project": {"key": settings.ticketing_project},
                        "summary": summary,
                        "description": description,
                        "issuetype": {"name": "Task"},
                        "priority": {"name": priority},
                        "labels": labels or ["threat-intel"],
                    }
                },
            )
            resp.raise_for_status()
            data = resp.json()

        ticket_id = data.get("key", data.get("id", ""))
        logger.info("ticketing.created", ticket_id=ticket_id)
        return {"ticket_id": ticket_id, "status": "created"}
    except Exception as exc:
        logger.warning("ticketing.create_error", error=str(exc))
        return {"ticket_id": "", "status": "error", "error": str(exc)}


def update_ticket_status(ticket_id: str, status: str, comment: str = "") -> bool:
    """Update the status of an existing ticket."""
    settings = _get_settings()
    if not settings.ticketing_url or not settings.ticketing_api_key:
        logger.warning("ticketing.not_configured")
        return True  # mock

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            if comment:
                client.post(
                    f"{settings.ticketing_url}/rest/api/2/issue/{ticket_id}/comment",
                    headers={"Authorization": f"Bearer {settings.ticketing_api_key}"},
                    json={"body": comment},
                )
            resp = client.post(
                f"{settings.ticketing_url}/rest/api/2/issue/{ticket_id}/transitions",
                headers={"Authorization": f"Bearer {settings.ticketing_api_key}"},
                json={"transition": {"name": status}},
            )
            resp.raise_for_status()
        return True
    except Exception as exc:
        logger.warning("ticketing.update_error", ticket_id=ticket_id, error=str(exc))
        return False
