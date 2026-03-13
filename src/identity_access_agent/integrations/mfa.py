"""MFA provider integration client (SRS-06 §8)."""

from __future__ import annotations

from typing import Any

import structlog

from identity_access_agent.config import get_settings

logger = structlog.get_logger(__name__)


def fetch_mfa_events(since: str | None = None) -> list[dict[str, Any]]:
    """Fetch MFA challenge/response telemetry."""
    settings = get_settings()
    logger.debug("fetch_mfa_events", mfa_url=settings.mfa_api_url, since=since)
    return []


def trigger_step_up_mfa(user_id: str) -> dict[str, Any]:
    """Request step-up MFA challenge for a user."""
    logger.info("trigger_step_up_mfa", user_id=user_id)
    return {"user_id": user_id, "status": "challenge_sent"}
