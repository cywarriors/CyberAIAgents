"""Integration: Commercial threat-intelligence feed client."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _get_settings():
    from threat_intelligence_agent.config import get_settings
    return get_settings()


def fetch_commercial_intel() -> list[dict[str, Any]]:
    """Fetch intelligence from a commercial feed (generic REST API client).

    Falls back to empty list when the feed URL / key is not configured.
    """
    settings = _get_settings()
    if not settings.commercial_feed_url or not settings.commercial_feed_api_key:
        logger.warning("commercial_feed.not_configured")
        return []

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.get(
                f"{settings.commercial_feed_url}/indicators/recent",
                headers={"Authorization": f"Bearer {settings.commercial_feed_api_key}"},
                params={"limit": 100},
            )
            resp.raise_for_status()
            data = resp.json()

        records: list[dict[str, Any]] = []
        for item in data.get("indicators", data.get("data", [])):
            value = item.get("value", item.get("indicator", ""))
            if not value:
                continue
            records.append(
                {
                    "source_name": "commercial",
                    "source_type": "commercial",
                    "tlp": item.get("tlp", "TLP:AMBER"),
                    "raw_payload": {
                        "indicators": [value],
                        "labels": item.get("tags", item.get("labels", [])),
                        "kill_chain_phases": item.get("kill_chain_phases", []),
                        "actor": item.get("actor", ""),
                        "campaign": item.get("campaign", ""),
                    },
                }
            )
        return records
    except Exception as exc:
        logger.warning("commercial_feed.fetch_error", error=str(exc))
        return []
