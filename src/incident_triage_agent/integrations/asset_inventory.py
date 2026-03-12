"""CMDB / Asset Inventory integration – host criticality and ownership."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)


def lookup_asset(host_name: str | None = None, ip: str | None = None) -> dict[str, Any]:
    """Look up asset criticality, ownership, and OS details from CMDB."""
    settings = get_settings()
    if not settings.cmdb_api_key:
        logger.warning("cmdb_lookup_skipped", reason="no API key configured")
        return {}

    url = f"{settings.cmdb_base_url}/assets"
    headers = {"Authorization": f"Bearer {settings.cmdb_api_key}"}
    params: dict[str, str] = {}
    if host_name:
        params["hostname"] = host_name
    if ip:
        params["ip"] = ip

    with httpx.Client(timeout=10) as client:
        resp = client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()
