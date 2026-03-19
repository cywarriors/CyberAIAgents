"""Threat intelligence connector."""
from __future__ import annotations


class ThreatIntelConnector:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url
        self.api_key = api_key

    def enrich_ip(self, ip: str) -> dict:
        """Enrich IP with threat intelligence context."""
        if not self.base_url:
            return {}
        return {"ip": ip, "reputation": "unknown"}
