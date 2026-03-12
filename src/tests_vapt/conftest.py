"""Shared fixtures for VAPT agent tests."""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Environment isolation – prevent real API calls
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _vapt_env(monkeypatch):
    """Set minimal env vars so Settings() never touches real services."""
    defaults = {
        "AGENT_ENV": "test",
        "LOG_LEVEL": "DEBUG",
        "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
        "KAFKA_SCAN_REQUESTS_TOPIC": "vapt.scan-requests.test",
        "KAFKA_FINDINGS_TOPIC": "vapt.findings.test",
        "REDIS_URL": "redis://localhost:6379/1",
        "NUCLEI_API_URL": "http://localhost:1111",
        "NUCLEI_API_KEY": "",
        "ZAP_API_URL": "http://localhost:2222",
        "ZAP_API_KEY": "",
        "NESSUS_API_URL": "http://localhost:3333",
        "NESSUS_API_KEY": "",
        "NVD_API_URL": "http://localhost:4444",
        "EPSS_API_URL": "http://localhost:5555",
        "KEV_CATALOG_URL": "http://localhost:6666/kev.json",
        "CMDB_API_URL": "http://localhost:7777",
        "CMDB_API_KEY": "",
        "TICKETING_API_URL": "http://localhost:8888",
        "TICKETING_API_KEY": "",
        "MESSAGING_WEBHOOK_URL": "",
        "CREDENTIAL_VAULT_URL": "",
        "CREDENTIAL_VAULT_TOKEN": "",
        "REPORT_OUTPUT_DIR": "/tmp/vapt_test_reports",
        "PROMETHEUS_PORT": "9191",
        "HEALTH_CHECK_PORT": "8183",
    }
    for k, v in defaults.items():
        monkeypatch.setenv(k, v)

    # Clear cached settings
    from vapt_agent.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Common fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def valid_roe() -> dict[str, Any]:
    from tests_vapt.mocks.generators import generate_valid_roe
    return generate_valid_roe()


@pytest.fixture()
def discovered_assets() -> list[dict[str, Any]]:
    from tests_vapt.mocks.generators import generate_discovered_assets
    return generate_discovered_assets(3)


@pytest.fixture()
def scan_findings(discovered_assets) -> list[dict[str, Any]]:
    from tests_vapt.mocks.generators import generate_scan_findings
    return generate_scan_findings(discovered_assets)


@pytest.fixture()
def full_state(valid_roe, discovered_assets, scan_findings) -> dict[str, Any]:
    """Complete engagement state for node tests."""
    from tests_vapt.mocks.generators import _uid
    exploits = []
    for f in scan_findings:
        exploits.append({
            "exploit_id": _uid(),
            "finding_id": f["finding_id"],
            "module_name": "stub/safe-check",
            "risk_level": "safe",
            "success": f["severity"] in ("critical", "high"),
            "rollback_success": True,
        })
    return {
        "engagement_id": _uid(),
        "roe_authorization": valid_roe,
        "roe_validated": True,
        "discovered_assets": discovered_assets,
        "scan_results": scan_findings,
        "validated_exploits": exploits,
        "attack_paths": [],
        "risk_scores": [],
        "remediation_items": [],
        "report_artifacts": [],
        "published_findings": [],
        "errors": [],
    }
