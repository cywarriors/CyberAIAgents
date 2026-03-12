"""Scanner engine integration – orchestrate Nmap, Nuclei, ZAP, Nessus."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from vapt_agent.config import get_settings

logger = structlog.get_logger(__name__)


def run_nmap_scan(targets: list[str], ports: str = "1-65535") -> list[dict[str, Any]]:
    """Execute Nmap scan against targets. Returns discovered hosts/ports."""
    settings = get_settings()
    logger.info("nmap_scan_start", targets=targets, ports=ports)
    # In production: subprocess call to nmap or integration with nmap API wrapper
    # This stub returns empty; mock generators provide test data
    logger.warning("nmap_scan_stub", reason="production scanner not configured")
    return []


def run_nuclei_scan(targets: list[str], templates: list[str] | None = None) -> list[dict[str, Any]]:
    """Execute Nuclei vulnerability scan against targets."""
    settings = get_settings()
    if not settings.nuclei_api_key:
        logger.warning("nuclei_scan_skipped", reason="no API key configured")
        return []

    url = f"{settings.nuclei_api_url}/scan"
    headers = {"Authorization": f"Bearer {settings.nuclei_api_key}"}
    payload: dict[str, Any] = {"targets": targets}
    if templates:
        payload["templates"] = templates
    with httpx.Client(timeout=300) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json().get("findings", [])


def run_zap_scan(target_url: str, scan_type: str = "active") -> list[dict[str, Any]]:
    """Execute ZAP web application scan."""
    settings = get_settings()
    if not settings.zap_api_key:
        logger.warning("zap_scan_skipped", reason="no API key configured")
        return []

    url = f"{settings.zap_api_url}/scan"
    headers = {"Authorization": f"Bearer {settings.zap_api_key}"}
    payload = {"target": target_url, "scan_type": scan_type}
    with httpx.Client(timeout=600) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json().get("alerts", [])


def run_nessus_scan(targets: list[str], policy: str = "default") -> list[dict[str, Any]]:
    """Execute Nessus vulnerability scan."""
    settings = get_settings()
    if not settings.nessus_api_key:
        logger.warning("nessus_scan_skipped", reason="no API key configured")
        return []

    url = f"{settings.nessus_api_url}/scans"
    headers = {"X-ApiKeys": f"accessKey={settings.nessus_api_key}"}
    payload = {"targets": targets, "policy": policy}
    with httpx.Client(timeout=600) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
