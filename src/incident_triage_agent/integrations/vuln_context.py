"""Vulnerability context integration – exposure data for entity enrichment."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)


def lookup_vulnerabilities(
    host_name: str | None = None, ip: str | None = None
) -> dict[str, Any]:
    """Fetch open vulnerability counts and critical exposure data."""
    settings = get_settings()
    if not settings.vuln_api_key:
        logger.warning("vuln_lookup_skipped", reason="no API key configured")
        return {}

    url = f"{settings.vuln_base_url}/hosts"
    headers = {"Authorization": f"Bearer {settings.vuln_api_key}"}
    params: dict[str, str] = {}
    if host_name:
        params["hostname"] = host_name
    if ip:
        params["ip"] = ip

    with httpx.Client(timeout=10) as client:
        resp = client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()
