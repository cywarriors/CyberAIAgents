"""Threat Intelligence Platform integration – IOC feed matching."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from threat_detection_agent.config import get_settings

logger = structlog.get_logger(__name__)


def fetch_ioc_feed(ioc_type: str = "all", limit: int = 5000) -> list[dict[str, Any]]:
    """Retrieve IOC indicators from the Threat Intel platform."""
    settings = get_settings()
    if not settings.threat_intel_api_key:
        logger.warning("threat_intel_skipped", reason="no API key configured")
        return []

    url = f"{settings.threat_intel_base_url}/indicators"
    headers = {"Authorization": f"Bearer {settings.threat_intel_api_key}"}
    params = {"type": ioc_type, "limit": limit}
    with httpx.Client(timeout=30) as client:
        resp = client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json().get("indicators", [])


def match_iocs(event: dict[str, Any], iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check if event fields match any known IOC."""
    matches: list[dict[str, Any]] = []
    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "")
    domain = event.get("domain", "")

    for ioc in iocs:
        indicator = ioc.get("value", "")
        ioc_type = ioc.get("type", "")
        if ioc_type == "ip" and indicator in (src_ip, dst_ip):
            matches.append(ioc)
        elif ioc_type == "domain" and indicator == domain:
            matches.append(ioc)
    return matches
