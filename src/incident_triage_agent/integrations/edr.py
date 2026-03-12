"""EDR integration – fetch endpoint detections for enrichment."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)


def fetch_edr_detections(host_name: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
    """Pull endpoint detections from EDR REST API."""
    settings = get_settings()
    if not settings.edr_api_key:
        logger.warning("edr_fetch_skipped", reason="no API key configured")
        return []

    url = f"{settings.edr_base_url}/detections"
    headers = {"Authorization": f"Bearer {settings.edr_api_key}"}
    params: dict[str, Any] = {"limit": limit}
    if host_name:
        params["host"] = host_name

    with httpx.Client(timeout=30) as client:
        resp = client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json().get("detections", [])
