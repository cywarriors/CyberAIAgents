"""CMDB / asset inventory integration – look up asset metadata."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from vapt_agent.config import get_settings

logger = structlog.get_logger(__name__)


def lookup_asset(ip: str | None = None, hostname: str | None = None) -> dict[str, Any] | None:
    """Query the CMDB for asset details by IP or hostname."""
    settings = get_settings()
    if not settings.cmdb_api_key:
        logger.warning("cmdb_lookup_skipped", reason="no API key configured")
        return None

    params: dict[str, str] = {}
    if ip:
        params["ip"] = ip
    if hostname:
        params["hostname"] = hostname

    url = f"{settings.cmdb_api_url}/assets"
    headers = {"Authorization": f"Bearer {settings.cmdb_api_key}"}
    with httpx.Client(timeout=15) as client:
        resp = client.get(url, params=params, headers=headers)
        resp.raise_for_status()
        results = resp.json().get("assets", [])
        return results[0] if results else None
