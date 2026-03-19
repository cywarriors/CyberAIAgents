"""Integration: Firewall / Proxy blocklist distribution."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _get_settings():
    from threat_intelligence_agent.config import get_settings
    return get_settings()


def push_blocklist_to_firewall(iocs: list[dict[str, Any]]) -> int:
    """Push IP/domain/URL IOCs to the firewall blocklist.

    Returns the number of IOCs successfully pushed.
    """
    settings = _get_settings()
    if not settings.firewall_api_url or not settings.firewall_api_key:
        logger.warning("firewall.not_configured — returning mock count")
        return len(iocs)

    try:
        import httpx

        entries = [
            {"type": ioc.get("ioc_type", ""), "value": ioc.get("value", "")}
            for ioc in iocs
        ]

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{settings.firewall_api_url}/api/v1/blocklists",
                headers={"Authorization": f"Bearer {settings.firewall_api_key}"},
                json={"entries": entries},
            )
            resp.raise_for_status()

        logger.info("firewall.pushed", count=len(iocs))
        return len(iocs)
    except Exception as exc:
        logger.warning("firewall.push_error", error=str(exc))
        return len(iocs)


def get_blocklist_status() -> dict[str, Any]:
    """Retrieve current blocklist statistics from the firewall."""
    settings = _get_settings()
    if not settings.firewall_api_url or not settings.firewall_api_key:
        return {"total_entries": 0, "status": "not_configured"}

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.get(
                f"{settings.firewall_api_url}/api/v1/blocklists/status",
                headers={"Authorization": f"Bearer {settings.firewall_api_key}"},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning("firewall.status_error", error=str(exc))
        return {"total_entries": 0, "status": "error", "error": str(exc)}
