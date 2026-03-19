"""conftest.py — test environment for Deception Honeypot Agent."""
from __future__ import annotations

import os

import pytest

_SAFE_ENV = {
    "DECEPTION_SIEM_API_URL": "",
    "DECEPTION_SIEM_API_KEY": "",
    "DECEPTION_THREAT_INTEL_API_URL": "",
    "DECEPTION_THREAT_INTEL_API_KEY": "",
    "DECEPTION_INFRA_API_URL": "",
    "DECEPTION_INFRA_API_KEY": "",
    "DECEPTION_ITSM_API_URL": "",
    "DECEPTION_ITSM_API_KEY": "",
    "DECEPTION_MAX_DECOYS": "50",
    "DECEPTION_ROTATION_INTERVAL_HOURS": "24",
    "DECEPTION_COVERAGE_TARGET_PERCENT": "80.0",
    "DECEPTION_API_PORT": "8012",
    "DECEPTION_HEALTH_PORT": "8092",
    "DECEPTION_METRICS_PORT": "9102",
    "DECEPTION_AGENT_ENV": "test",
    "DECEPTION_LOG_LEVEL": "WARNING",
}

for k, v in _SAFE_ENV.items():
    os.environ.setdefault(k, v)


@pytest.fixture(autouse=True, scope="session")
def _neutralise_settings():
    from deception_honeypot_agent.config import get_settings

    get_settings.cache_clear()
    for k, v in _SAFE_ENV.items():
        os.environ[k] = v
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_store():
    from deception_honeypot_agent.api.store import get_data_store

    get_data_store.cache_clear()
    yield
    get_data_store.cache_clear()


@pytest.fixture
def empty_state() -> dict:
    return {
        "decoy_inventory": [],
        "honey_credentials": [],
        "canary_tokens": [],
        "interactions": [],
        "classified_interactions": [],
        "ttp_mappings": [],
        "alerts": [],
        "attacker_profiles": [],
        "coverage_assessment": {},
        "rotation_actions": [],
        "processing_errors": [],
    }


@pytest.fixture(scope="module")
def api_app():
    from deception_honeypot_agent.api.app import app

    return app
