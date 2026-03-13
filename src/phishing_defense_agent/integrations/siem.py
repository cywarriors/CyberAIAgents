"""SIEM client – alert and IOC publishing."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from phishing_defense_agent.config import get_settings

logger = structlog.get_logger(__name__)


def publish_verdict(verdict: dict[str, Any]) -> bool:
    """Publish phishing verdict record to SIEM."""
    settings = get_settings()
    if not settings.siem_api_key:
        logger.warning("siem_publish_skipped", reason="no API key configured")
        return False

    url = f"{settings.siem_base_url}/events"
    headers = {"Authorization": f"Bearer {settings.siem_api_key}"}

    event = {
        "event_type": "phishing_verdict",
        "source": "phishing-defense-agent",
        "message_id": verdict.get("message_id"),
        "verdict": verdict.get("verdict"),
        "action": verdict.get("action"),
        "risk_score": verdict.get("risk_score"),
        "sender": verdict.get("sender_address"),
        "subject": verdict.get("subject"),
        "processed_at": verdict.get("processed_at"),
    }

    with httpx.Client(timeout=10) as client:
        resp = client.post(url, json=event, headers=headers)
        resp.raise_for_status()

    logger.info("verdict_published_to_siem", message_id=verdict.get("message_id"))
    return True


def publish_iocs(iocs: list[dict[str, Any]]) -> bool:
    """Publish extracted IOCs to SIEM for correlation."""
    settings = get_settings()
    if not settings.siem_api_key:
        logger.warning("siem_ioc_publish_skipped", reason="no API key configured")
        return False

    url = f"{settings.siem_base_url}/iocs"
    headers = {"Authorization": f"Bearer {settings.siem_api_key}"}

    with httpx.Client(timeout=10) as client:
        resp = client.post(url, json={"iocs": iocs}, headers=headers)
        resp.raise_for_status()

    logger.info("iocs_published_to_siem", count=len(iocs))
    return True
