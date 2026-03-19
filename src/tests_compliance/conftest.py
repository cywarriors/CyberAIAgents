"""conftest.py – test environment setup for the Compliance and Audit Agent."""

from __future__ import annotations

import os
import pytest

_SAFE_ENV = {
    "COMPLIANCE_KAFKA_BOOTSTRAP": "localhost:9092",
    "COMPLIANCE_KAFKA_TOPIC": "test-compliance",
    "COMPLIANCE_KAFKA_GROUP_ID": "test-group",
    "COMPLIANCE_REDIS_URL": "redis://localhost:6379/15",
    "COMPLIANCE_POSTGRES_DSN": "postgresql://test:test@localhost:5432/test",
    "COMPLIANCE_SIEM_API_URL": "",
    "COMPLIANCE_SIEM_API_KEY": "",
    "COMPLIANCE_IAM_API_URL": "",
    "COMPLIANCE_IAM_API_KEY": "",
    "COMPLIANCE_AWS_API_URL": "",
    "COMPLIANCE_AWS_API_KEY": "",
    "COMPLIANCE_ITSM_API_URL": "",
    "COMPLIANCE_ITSM_API_KEY": "",
    "COMPLIANCE_ENABLED_FRAMEWORKS": "ISO27001,NIST_CSF,SOC2",
    "COMPLIANCE_ORG_UNIT": "test_unit",
    "COMPLIANCE_EFFECTIVENESS_THRESHOLD_FULL": "85.0",
    "COMPLIANCE_EFFECTIVENESS_THRESHOLD_PARTIAL": "60.0",
    "COMPLIANCE_COMPLIANCE_DRIFT_ALERT_THRESHOLD": "5.0",
    "COMPLIANCE_API_PORT": "8010",
    "COMPLIANCE_HEALTH_PORT": "8090",
    "COMPLIANCE_METRICS_PORT": "9100",
    "COMPLIANCE_AGENT_ENV": "test",
    "COMPLIANCE_LOG_LEVEL": "WARNING",
}

for key, val in _SAFE_ENV.items():
    os.environ.setdefault(key, val)


@pytest.fixture(autouse=True, scope="session")
def _neutralise_settings():
    from compliance_audit_agent.config import get_settings
    get_settings.cache_clear()
    for key, val in _SAFE_ENV.items():
        os.environ[key] = val
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_store():
    from compliance_audit_agent.api.store import get_data_store
    from compliance_audit_agent.monitoring.store import get_store
    get_data_store.cache_clear()
    get_store.cache_clear()
    yield
    get_data_store.cache_clear()
    get_store.cache_clear()


@pytest.fixture
def empty_state() -> dict:
    return {
        "evidence_items": [],
        "control_mappings": [],
        "effectiveness_scores": {},
        "gaps": [],
        "framework_scores": {},
        "audit_packs": [],
        "drift_alerts": [],
        "remediation_tickets": [],
        "processing_errors": [],
    }


@pytest.fixture(scope="module")
def api_app():
    from compliance_audit_agent.api.app import app
    return app
