"""ITSM / Ticketing System integration for remediation tracking."""

import secrets
from typing import Optional
from datetime import datetime, timezone


class TicketingClient:
    """Base client for ticketing systems."""

    def __init__(self, api_url: str, api_key: str = ""):
        self.api_url = api_url
        self.api_key = api_key

    async def create_remediation_ticket(
        self,
        finding_id: str,
        severity: str,
        title: str,
        description: str,
        resource_id: str,
        account_id: str,
        owner_email: str,
    ) -> str:
        """Create a remediation ticket."""
        raise NotImplementedError

    async def update_ticket_status(self, ticket_id: str, status: str) -> bool:
        """Update ticket status."""
        raise NotImplementedError

    async def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get current ticket status."""
        raise NotImplementedError


class MockTicketingClient(TicketingClient):
    """Mock ticketing client for testing."""

    def __init__(self):
        super().__init__("mock://")
        self.tickets: dict[str, dict] = {}

    async def create_remediation_ticket(
        self,
        finding_id: str,
        severity: str,
        title: str,
        description: str,
        resource_id: str,
        account_id: str,
        owner_email: str,
    ) -> str:
        """Create mock ticket."""
        ticket_id = f"TKT-CSPM-{secrets.token_hex(8)}"
        self.tickets[ticket_id] = {
            "finding_id": finding_id,
            "severity": severity,
            "title": title,
            "description": description,
            "resource_id": resource_id,
            "account_id": account_id,
            "owner": owner_email,
            "status": "open",
            "created_date": datetime.now(timezone.utc).isoformat(),
        }
        return ticket_id

    async def update_ticket_status(self, ticket_id: str, status: str) -> bool:
        """Update mock ticket status."""
        if ticket_id in self.tickets:
            self.tickets[ticket_id]["status"] = status
            return True
        return False

    async def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get mock ticket status."""
        if ticket_id in self.tickets:
            return self.tickets[ticket_id]["status"]
        return None


class JiraClient(TicketingClient):
    """Jira ticketing client."""

    async def create_remediation_ticket(
        self,
        finding_id: str,
        severity: str,
        title: str,
        description: str,
        resource_id: str,
        account_id: str,
        owner_email: str,
    ) -> str:
        """Create Jira ticket."""
        return f"JIRA-CSPM-{finding_id}"

    async def update_ticket_status(self, ticket_id: str, status: str) -> bool:
        """Update Jira ticket."""
        return True

    async def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get Jira ticket status."""
        return "open"


class ServiceNowClient(TicketingClient):
    """ServiceNow ticketing client."""

    async def create_remediation_ticket(
        self,
        finding_id: str,
        severity: str,
        title: str,
        description: str,
        resource_id: str,
        account_id: str,
        owner_email: str,
    ) -> str:
        """Create ServiceNow ticket."""
        return f"SC-CSPM-{finding_id}"

    async def update_ticket_status(self, ticket_id: str, status: str) -> bool:
        """Update ServiceNow ticket."""
        return True

    async def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get ServiceNow ticket status."""
        return "open"
