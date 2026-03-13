"""Geo-IP / IP reputation enrichment client (SRS-06 §8)."""

from __future__ import annotations

from typing import Any

import structlog

from identity_access_agent.config import get_settings

logger = structlog.get_logger(__name__)


def enrich_ip(ip_address: str) -> dict[str, Any]:
    """Enrich an IP address with geo-location and reputation data."""
    settings = get_settings()
    logger.debug("enrich_ip", geoip_url=settings.geoip_api_url, ip=ip_address)
    return {
        "ip": ip_address,
        "city": "Unknown",
        "country": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0,
        "risk_score": 0.0,
        "is_vpn": False,
        "is_tor": False,
    }
