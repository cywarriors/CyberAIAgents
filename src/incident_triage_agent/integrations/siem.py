"""SIEM integration – ingest alerts and fetch related events."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)


def fetch_alerts_from_siem(query: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
    """Pull alerts from SIEM search API."""
    settings = get_settings()
    if not settings.siem_api_key:
        logger.warning("siem_fetch_skipped", reason="no API key configured")
        return []

    url = f"{settings.siem_base_url}/alerts"
    headers = {"Authorization": f"Bearer {settings.siem_api_key}"}
    params: dict[str, Any] = {"limit": limit}
    if query:
        params["query"] = query

    with httpx.Client(timeout=30) as client:
        resp = client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json().get("alerts", [])


def fetch_related_events(alert_id: str, time_window_minutes: int = 30) -> list[dict[str, Any]]:
    """Fetch events related to an alert within a time window."""
    settings = get_settings()
    if not settings.siem_api_key:
        logger.warning("siem_related_events_skipped", reason="no API key configured")
        return []

    url = f"{settings.siem_base_url}/events"
    headers = {"Authorization": f"Bearer {settings.siem_api_key}"}
    params = {"related_alert": alert_id, "window_minutes": time_window_minutes}

    with httpx.Client(timeout=30) as client:
        resp = client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json().get("events", [])
