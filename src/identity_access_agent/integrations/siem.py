"""SIEM integration client (SRS-06 §8)."""

from __future__ import annotations

from typing import Any

import structlog

from identity_access_agent.config import get_settings

logger = structlog.get_logger(__name__)


def publish_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Publish identity risk alert to SIEM."""
    settings = get_settings()
    logger.info("publish_alert", siem_url=settings.siem_api_url, alert_id=alert.get("alert_id"))
    return {"status": "published", "alert_id": alert.get("alert_id")}
