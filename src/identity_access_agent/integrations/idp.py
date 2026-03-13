"""IdP integration client – Entra ID / Okta / Ping (SRS-06 §8)."""

from __future__ import annotations

from typing import Any

import structlog

from identity_access_agent.config import get_settings

logger = structlog.get_logger(__name__)


def fetch_auth_events(since: str | None = None) -> list[dict[str, Any]]:
    """Fetch authentication events from Identity Provider.

    In production this calls the IdP REST API / SCIM endpoint.
    Returns an empty list when the service is unavailable.
    """
    settings = get_settings()
    logger.debug("fetch_auth_events", idp_url=settings.idp_api_url, since=since)
    return []


def fetch_user_directory() -> list[dict[str, Any]]:
    """Fetch user directory / profile data from IdP."""
    logger.debug("fetch_user_directory")
    return []


def fetch_role_catalog() -> list[dict[str, Any]]:
    """Fetch role/permission catalog from IAM system."""
    logger.debug("fetch_role_catalog")
    return []
