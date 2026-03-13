"""SIEM integration for forwarding high-risk cloud security findings."""

import secrets
from typing import Optional
from datetime import datetime, timezone


class SIEMClient:
    """Base SIEM client for sending alerts."""

    def __init__(self, api_url: str, api_key: str = ""):
        self.api_url = api_url
        self.api_key = api_key

    async def send_alert(
        self,
        finding_id: str,
        severity: str,
        title: str,
        description: str,
        resource_id: str,
        account_id: str,
        provider: str,
    ) -> str:
        """Send an alert to SIEM."""
        raise NotImplementedError

    async def send_batch_alerts(self, alerts: list[dict]) -> list[str]:
        """Send multiple alerts."""
        raise NotImplementedError


class MockSIEMClient(SIEMClient):
    """Mock SIEM client for testing."""

    def __init__(self):
        super().__init__("mock://")
        self.sent_alerts: list[dict] = []

    async def send_alert(
        self,
        finding_id: str,
        severity: str,
        title: str,
        description: str,
        resource_id: str,
        account_id: str,
        provider: str,
    ) -> str:
        """Send mock alert."""
        alert_id = f"SIEM-{secrets.token_hex(8)}"
        self.sent_alerts.append({
            "alert_id": alert_id,
            "finding_id": finding_id,
            "severity": severity,
            "title": title,
            "description": description,
            "resource_id": resource_id,
            "account_id": account_id,
            "provider": provider,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        })
        return alert_id

    async def send_batch_alerts(self, alerts: list[dict]) -> list[str]:
        """Send batch of mock alerts."""
        alert_ids = []
        for alert in alerts:
            alert_id = await self.send_alert(**alert)
            alert_ids.append(alert_id)
        return alert_ids
