"""Threat Intelligence integration – IOC and TTP context for enrichment."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)


def fetch_threat_context(mitre_ids: list[str]) -> list[dict[str, Any]]:
    """Retrieve TTP context and IOC associations for given MITRE technique IDs."""
    settings = get_settings()
    if not settings.threat_intel_api_key:
        logger.warning("threat_intel_skipped", reason="no API key configured")
        return []

    url = f"{settings.threat_intel_base_url}/ttp_context"
    headers = {"Authorization": f"Bearer {settings.threat_intel_api_key}"}
    params = {"technique_ids": ",".join(mitre_ids)}

    with httpx.Client(timeout=30) as client:
        resp = client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json().get("context", [])


def check_ioc_matches(indicators: list[str]) -> list[dict[str, Any]]:
    """Check if given indicators match known IOCs."""
    settings = get_settings()
    if not settings.threat_intel_api_key:
        logger.warning("ioc_check_skipped", reason="no API key configured")
        return []

    url = f"{settings.threat_intel_base_url}/ioc/check"
    headers = {"Authorization": f"Bearer {settings.threat_intel_api_key}"}
    payload = {"indicators": indicators}

    with httpx.Client(timeout=30) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json().get("matches", [])
