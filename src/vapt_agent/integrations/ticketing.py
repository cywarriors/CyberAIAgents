"""Ticketing integration – create remediation tickets in ServiceNow / Jira."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from vapt_agent.config import get_settings

logger = structlog.get_logger(__name__)


def create_ticket(finding: dict[str, Any]) -> str | None:
    """Create a remediation ticket and return the ticket ID."""
    settings = get_settings()
    if not settings.ticketing_api_key:
        logger.warning("ticketing_skipped", reason="no API key configured")
        return None

    url = f"{settings.ticketing_api_url}/tickets"
    headers = {
        "Authorization": f"Bearer {settings.ticketing_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "title": f"[VAPT] {finding.get('title', 'Vulnerability Finding')}",
        "description": finding.get("description", ""),
        "severity": finding.get("severity", "medium"),
        "cve_id": finding.get("cve_id"),
        "asset_id": finding.get("asset_id"),
        "remediation": finding.get("remediation"),
        "engagement_id": finding.get("engagement_id"),
    }
    with httpx.Client(timeout=30) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json().get("ticket_id")
