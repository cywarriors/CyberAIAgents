"""Identity Directory integration – user context enrichment (LDAP / Graph API)."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from incident_triage_agent.config import get_settings

logger = structlog.get_logger(__name__)


def lookup_user(user_name: str) -> dict[str, Any]:
    """Fetch user profile including role, department, and privilege status."""
    settings = get_settings()
    if not settings.identity_api_key:
        logger.warning("identity_lookup_skipped", reason="no API key configured")
        return {}

    url = f"{settings.identity_base_url}/users/{user_name}"
    headers = {"Authorization": f"Bearer {settings.identity_api_key}"}

    with httpx.Client(timeout=10) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()
