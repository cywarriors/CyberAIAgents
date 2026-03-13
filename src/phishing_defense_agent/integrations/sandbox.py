"""Sandbox client – URL and attachment detonation."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from phishing_defense_agent.config import get_settings

logger = structlog.get_logger(__name__)


def detonate_url(url: str) -> dict[str, Any]:
    """Submit a URL to the sandbox for behavioral analysis."""
    settings = get_settings()
    if not settings.sandbox_api_key:
        logger.warning("sandbox_url_skipped", reason="no API key configured")
        return {
            "url": url,
            "sandbox_verdict": "clean",
            "is_known_phishing": False,
            "is_shortened": False,
            "redirect_chain": [],
            "threat_categories": [],
        }

    api_url = f"{settings.sandbox_base_url}/detonate/url"
    headers = {"Authorization": f"Bearer {settings.sandbox_api_key}"}

    try:
        with httpx.Client(timeout=settings.sandbox_timeout_seconds) as client:
            resp = client.post(api_url, headers=headers, json={"url": url})
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.warning("sandbox_url_timeout", url=url[:100])
        return {"url": url, "sandbox_verdict": "timeout", "is_known_phishing": False}
    except httpx.HTTPStatusError:
        logger.exception("sandbox_url_error", url=url[:100])
        return {"url": url, "sandbox_verdict": "error", "is_known_phishing": False}


def detonate_attachment(filename: str, file_hash: str) -> dict[str, Any]:
    """Submit an attachment to the sandbox for behavioral analysis."""
    settings = get_settings()
    if not settings.sandbox_api_key:
        logger.warning("sandbox_attachment_skipped", reason="no API key configured")
        return {
            "filename": filename,
            "file_hash": file_hash,
            "sandbox_verdict": "clean",
            "malware_family": "",
            "behavioral_indicators": [],
            "iocs_extracted": [],
        }

    api_url = f"{settings.sandbox_base_url}/detonate/file"
    headers = {"Authorization": f"Bearer {settings.sandbox_api_key}"}

    try:
        with httpx.Client(timeout=settings.sandbox_timeout_seconds) as client:
            resp = client.post(
                api_url, headers=headers,
                json={"filename": filename, "file_hash": file_hash},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.warning("sandbox_attachment_timeout", filename=filename)
        return {"filename": filename, "file_hash": file_hash, "sandbox_verdict": "timeout"}
    except httpx.HTTPStatusError:
        logger.exception("sandbox_attachment_error", filename=filename)
        return {"filename": filename, "file_hash": file_hash, "sandbox_verdict": "error"}
