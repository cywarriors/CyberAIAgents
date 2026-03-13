"""Threat intelligence client – IOC matching and distribution."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from phishing_defense_agent.config import get_settings

logger = structlog.get_logger(__name__)


def check_ioc_matches(indicators: list[str]) -> list[dict[str, Any]]:
    """Check if indicators match known phishing IOCs."""
    settings = get_settings()
    if not settings.threat_intel_api_key:
        logger.warning("ioc_check_skipped", reason="no API key configured")
        return []

    url = f"{settings.threat_intel_base_url}/ioc/check"
    headers = {"Authorization": f"Bearer {settings.threat_intel_api_key}"}

    with httpx.Client(timeout=30) as client:
        resp = client.post(url, json={"indicators": indicators}, headers=headers)
        resp.raise_for_status()
        return resp.json().get("matches", [])


def distribute_iocs(iocs: list[dict[str, Any]]) -> bool:
    """Distribute extracted IOCs to blocking systems and SIEM."""
    settings = get_settings()
    if not settings.threat_intel_api_key:
        logger.warning("ioc_distribute_skipped", reason="no API key configured")
        return False

    url = f"{settings.threat_intel_base_url}/ioc/ingest"
    headers = {"Authorization": f"Bearer {settings.threat_intel_api_key}"}

    with httpx.Client(timeout=15) as client:
        resp = client.post(url, json={"iocs": iocs}, headers=headers)
        resp.raise_for_status()

    logger.info("iocs_distributed", count=len(iocs))
    return True


def fetch_known_phishing_domains() -> list[str]:
    """Fetch list of known phishing domains from threat intelligence."""
    settings = get_settings()
    if not settings.threat_intel_api_key:
        return []

    url = f"{settings.threat_intel_base_url}/feeds/phishing_domains"
    headers = {"Authorization": f"Bearer {settings.threat_intel_api_key}"}

    with httpx.Client(timeout=30) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json().get("domains", [])
