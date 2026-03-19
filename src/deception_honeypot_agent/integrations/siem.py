"""SIEM connector for forwarding honeypot alerts."""
from __future__ import annotations


class SIEMConnector:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url
        self.api_key = api_key

    def send_alert(self, alert: dict) -> bool:
        """Send alert to SIEM. Returns True on success."""
        if not self.base_url:
            return False
        # Real implementation would POST to SIEM API
        return True
