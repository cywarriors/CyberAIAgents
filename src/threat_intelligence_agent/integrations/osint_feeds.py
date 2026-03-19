"""Integration: OSINT feed clients (AlienVault OTX, abuse.ch, CIRCL TAXII)."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _get_settings():
    from threat_intelligence_agent.config import get_settings
    return get_settings()


def fetch_otx_pulses() -> list[dict[str, Any]]:
    """Fetch recent pulses from AlienVault OTX.

    Returns a list of raw intel records.  Falls back to empty list when
    the API key is not configured.
    """
    settings = _get_settings()
    if not settings.otx_api_key:
        logger.warning("osint.otx_api_key_not_set")
        return []

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.get(
                f"{settings.otx_base_url}/pulses/subscribed",
                headers={"X-OTX-API-KEY": settings.otx_api_key},
                params={"limit": 50, "modified_since": ""},
            )
            resp.raise_for_status()
            data = resp.json()

        records: list[dict[str, Any]] = []
        for pulse in data.get("results", []):
            indicators = [
                ioc.get("indicator", "")
                for ioc in pulse.get("indicators", [])
                if ioc.get("indicator")
            ]
            records.append(
                {
                    "source_name": "otx",
                    "source_type": "osint",
                    "tlp": "TLP:WHITE",
                    "raw_payload": {
                        "indicators": indicators,
                        "labels": pulse.get("tags", []),
                        "kill_chain_phases": [],
                    },
                }
            )
        return records
    except Exception as exc:
        logger.warning("osint.otx_fetch_error", error=str(exc))
        return []


def fetch_abusech_feed() -> list[dict[str, Any]]:
    """Fetch recent URLs/hashes from abuse.ch URLhaus / MalwareBazaar."""
    settings = _get_settings()
    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{settings.abusech_base_url}/payloads/recent/",
                data={"selector": "time"},
            )
            resp.raise_for_status()
            data = resp.json()

        records: list[dict[str, Any]] = []
        for entry in data.get("payloads", [])[:100]:
            indicators = []
            if entry.get("sha256_hash"):
                indicators.append(entry["sha256_hash"])
            if entry.get("md5_hash"):
                indicators.append(entry["md5_hash"])
            records.append(
                {
                    "source_name": "abusech",
                    "source_type": "osint",
                    "tlp": "TLP:WHITE",
                    "raw_payload": {
                        "indicators": indicators,
                        "labels": ["malware", entry.get("file_type", "")],
                        "kill_chain_phases": ["delivery"],
                    },
                }
            )
        return records
    except Exception as exc:
        logger.warning("osint.abusech_fetch_error", error=str(exc))
        return []


def fetch_circl_taxii() -> list[dict[str, Any]]:
    """Fetch intelligence from CIRCL TAXII feed (simplified REST fallback)."""
    settings = _get_settings()
    if not settings.circl_taxii_url:
        logger.warning("osint.circl_url_not_set")
        return []

    try:
        import httpx

        with httpx.Client(timeout=30) as client:
            resp = client.get(
                settings.circl_taxii_url,
                headers={"Accept": "application/taxii+json;version=2.1"},
            )
            resp.raise_for_status()
            data = resp.json()

        records: list[dict[str, Any]] = []
        for obj in data.get("objects", [])[:100]:
            pattern = obj.get("pattern", "")
            value = ""
            if "'" in pattern:
                value = pattern.split("'")[1]
            if value:
                records.append(
                    {
                        "source_name": "circl",
                        "source_type": "osint",
                        "tlp": "TLP:GREEN",
                        "raw_payload": {
                            "indicators": [value],
                            "labels": obj.get("labels", []),
                            "kill_chain_phases": [
                                kc.get("phase_name", "") for kc in obj.get("kill_chain_phases", [])
                            ],
                        },
                    }
                )
        return records
    except Exception as exc:
        logger.warning("osint.circl_fetch_error", error=str(exc))
        return []
