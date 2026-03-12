"""Credential vault integration – retrieve secrets for authenticated scanning."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from vapt_agent.config import get_settings

logger = structlog.get_logger(__name__)


def get_credential(secret_path: str) -> dict[str, Any] | None:
    """Retrieve a credential from the configured vault."""
    settings = get_settings()
    if not settings.credential_vault_url or not settings.credential_vault_token:
        logger.warning(
            "vault_skipped", reason="vault URL or token not configured"
        )
        return None

    url = f"{settings.credential_vault_url}/v1/{secret_path}"
    headers = {"X-Vault-Token": settings.credential_vault_token}
    with httpx.Client(timeout=15) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        payload = resp.json()
        return payload.get("data", {}).get("data")
