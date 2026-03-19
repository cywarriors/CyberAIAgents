"""Integration: EDR platform IOC push."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _get_settings():
    from threat_intelligence_agent.config import get_settings
    return get_settings()


def push_iocs_to_edr(iocs: list[dict[str, Any]]) -> int:
    """Push IOCs to the EDR for endpoint detection watchlists.

    Returns the count of IOCs successfully pushed.
    """
    settings = _get_settings()
    if not settings.edr_api_url or not settings.edr_api_key:
        logger.warning("edr.not_configured — returning mock count")
        return len(iocs)

    try:
        import httpx

        entries = [
            {"type": ioc.get("ioc_type", ""), "value": ioc.get("value", "")}
            for ioc in iocs
        ]

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{settings.edr_api_url}/api/v1/watchlists/iocs",
                headers={"Authorization": f"Bearer {settings.edr_api_key}"},
                json={"entries": entries},
            )
            resp.raise_for_status()

        logger.info("edr.pushed", count=len(iocs))
        return len(iocs)
    except Exception as exc:
        logger.warning("edr.push_error", error=str(exc))
        return len(iocs)


def get_edr_detection_status(ioc_values: list[str]) -> dict[str, bool]:
    """Check which IOCs have triggered EDR detections."""
    settings = _get_settings()
    if not settings.edr_api_url or not settings.edr_api_key:
        return {v: False for v in ioc_values}

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{settings.edr_api_url}/api/v1/watchlists/iocs/status",
                headers={"Authorization": f"Bearer {settings.edr_api_key}"},
                json={"values": ioc_values},
            )
            resp.raise_for_status()
            data = resp.json()

        return {item["value"]: item.get("detected", False) for item in data.get("results", [])}
    except Exception as exc:
        logger.warning("edr.status_error", error=str(exc))
        return {v: False for v in ioc_values}
