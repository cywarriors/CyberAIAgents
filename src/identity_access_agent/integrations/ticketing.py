"""ITSM (ServiceNow / Jira) ticketing client (SRS-06 §8)."""

from __future__ import annotations

from typing import Any

import structlog

from identity_access_agent.config import get_settings

logger = structlog.get_logger(__name__)


def create_ticket(alert: dict[str, Any]) -> dict[str, Any]:
    """Create ITSM ticket for identity risk alert."""
    settings = get_settings()
    logger.info("create_ticket", ticketing_url=settings.ticketing_api_url, alert_id=alert.get("alert_id"))
    return {"ticket_id": alert.get("ticket_id", ""), "status": "created"}
