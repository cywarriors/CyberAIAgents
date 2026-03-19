"""Integration: ISAC (Information Sharing and Analysis Center) feed client."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _get_settings():
    from threat_intelligence_agent.config import get_settings
    return get_settings()


def fetch_isac_intel() -> list[dict[str, Any]]:
    """Fetch sector-specific intelligence from an ISAC STIX/TAXII endpoint."""
    settings = _get_settings()
    if not settings.isac_taxii_url or not settings.isac_api_key:
        logger.warning("isac.not_configured")
        return []

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.get(
                f"{settings.isac_taxii_url}/collections/default/objects",
                headers={
                    "Authorization": f"Bearer {settings.isac_api_key}",
                    "Accept": "application/taxii+json;version=2.1",
                },
                params={"limit": 100},
            )
            resp.raise_for_status()
            data = resp.json()

        records: list[dict[str, Any]] = []
        for obj in data.get("objects", []):
            pattern = obj.get("pattern", "")
            value = ""
            if "'" in pattern:
                value = pattern.split("'")[1]
            if value:
                records.append(
                    {
                        "source_name": "isac",
                        "source_type": "isac",
                        "tlp": obj.get("tlp", "TLP:AMBER"),
                        "raw_payload": {
                            "indicators": [value],
                            "labels": obj.get("labels", []),
                            "kill_chain_phases": [
                                kc.get("phase_name", "")
                                for kc in obj.get("kill_chain_phases", [])
                            ],
                            "actor": obj.get("created_by_ref", ""),
                            "campaign": "",
                        },
                    }
                )
        return records
    except Exception as exc:
        logger.warning("isac.fetch_error", error=str(exc))
        return []


def share_intel_to_isac(stix_objects: list[dict[str, Any]]) -> int:
    """Share intelligence objects back to the ISAC (bidirectional).

    Only shares objects that are TLP:GREEN or TLP:WHITE.
    Returns the number of objects successfully shared.
    """
    settings = _get_settings()
    if not settings.isac_taxii_url or not settings.isac_api_key:
        logger.warning("isac.share_not_configured")
        return 0

    shareable = [
        obj for obj in stix_objects
        if obj.get("tlp", "TLP:GREEN") in ("TLP:GREEN", "TLP:WHITE")
    ]
    if not shareable:
        return 0

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{settings.isac_taxii_url}/collections/default/objects",
                headers={
                    "Authorization": f"Bearer {settings.isac_api_key}",
                    "Content-Type": "application/taxii+json;version=2.1",
                },
                json={"objects": shareable},
            )
            resp.raise_for_status()
        logger.info("isac.shared", count=len(shareable))
        return len(shareable)
    except Exception as exc:
        logger.warning("isac.share_error", error=str(exc))
        return 0
