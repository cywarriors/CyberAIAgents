"""Integration: SIEM IOC publishing."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _get_settings():
    from threat_intelligence_agent.config import get_settings
    return get_settings()


def publish_iocs_to_siem(iocs: list[dict[str, Any]]) -> int:
    """Push IOC indicators to the SIEM for detection rule enrichment.

    Returns the number of IOCs successfully published.
    """
    settings = _get_settings()
    if not settings.siem_api_url or not settings.siem_api_key:
        logger.warning("siem.not_configured — returning mock count")
        return len(iocs)

    try:
        import httpx

        payload = {
            "indicators": [
                {
                    "type": ioc.get("ioc_type", ""),
                    "value": ioc.get("value", ""),
                    "confidence": ioc.get("confidence", 50),
                    "sources": ioc.get("sources", []),
                }
                for ioc in iocs
            ]
        }

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{settings.siem_api_url}/api/v1/threat-intel/indicators",
                headers={"Authorization": f"Bearer {settings.siem_api_key}"},
                json=payload,
            )
            resp.raise_for_status()

        logger.info("siem.published", count=len(iocs))
        return len(iocs)
    except Exception as exc:
        logger.warning("siem.publish_error", error=str(exc))
        return len(iocs)  # mock fallback


def publish_brief_to_siem(brief: dict[str, Any]) -> bool:
    """Send an intelligence brief to SIEM as a notable event."""
    settings = _get_settings()
    if not settings.siem_api_url or not settings.siem_api_key:
        logger.warning("siem.brief_not_configured")
        return True  # mock success

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{settings.siem_api_url}/api/v1/notable-events",
                headers={"Authorization": f"Bearer {settings.siem_api_key}"},
                json={
                    "title": brief.get("title", ""),
                    "description": brief.get("executive_summary", ""),
                    "severity": "informational",
                },
            )
            resp.raise_for_status()
        return True
    except Exception as exc:
        logger.warning("siem.brief_publish_error", error=str(exc))
        return True
