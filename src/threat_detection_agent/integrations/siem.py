"""SIEM integration – publish alerts and ingest events."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from threat_detection_agent.config import get_settings

logger = structlog.get_logger(__name__)


def publish_to_siem(alert: dict[str, Any]) -> None:
    """POST alert to the SIEM REST API."""
    settings = get_settings()
    if not settings.siem_api_key:
        logger.warning("siem_publish_skipped", reason="no API key configured")
        return

    url = f"{settings.siem_base_url}/alerts"
    headers = {"Authorization": f"Bearer {settings.siem_api_key}"}
    with httpx.Client(timeout=10) as client:
        resp = client.post(url, json=alert, headers=headers)
        resp.raise_for_status()
    logger.info("siem_alert_published", alert_id=alert.get("alert_id"))


def fetch_events_from_siem(query: str, limit: int = 1000) -> list[dict[str, Any]]:
    """Pull events from SIEM search API (used for on-demand ingestion)."""
    settings = get_settings()
    if not settings.siem_api_key:
        logger.warning("siem_fetch_skipped", reason="no API key configured")
        return []

    url = f"{settings.siem_base_url}/events/search"
    headers = {"Authorization": f"Bearer {settings.siem_api_key}"}
    with httpx.Client(timeout=30) as client:
        resp = client.post(url, json={"query": query, "limit": limit}, headers=headers)
        resp.raise_for_status()
        return resp.json().get("events", [])
