"""conftest.py — test environment for Security Code Review Agent."""
from __future__ import annotations
import os
import pytest

_SAFE_ENV = {
    "CODE_REVIEW_VCS_API_URL": "",
    "CODE_REVIEW_VCS_API_TOKEN": "",
    "CODE_REVIEW_VCS_PLATFORM": "github",
    "CODE_REVIEW_NVD_API_URL": "",
    "CODE_REVIEW_NVD_API_KEY": "",
    "CODE_REVIEW_OSV_API_URL": "",
    "CODE_REVIEW_ITSM_API_URL": "",
    "CODE_REVIEW_ITSM_API_KEY": "",
    "CODE_REVIEW_SIEM_API_URL": "",
    "CODE_REVIEW_SIEM_API_KEY": "",
    "CODE_REVIEW_POLICY_BLOCK_SEVERITY": "critical",
    "CODE_REVIEW_POLICY_WARN_SEVERITY": "high",
    "CODE_REVIEW_SUPPORTED_LANGUAGES": "python,javascript,java,go,csharp",
    "CODE_REVIEW_API_PORT": "8011",
    "CODE_REVIEW_HEALTH_PORT": "8091",
    "CODE_REVIEW_METRICS_PORT": "9101",
    "CODE_REVIEW_AGENT_ENV": "test",
    "CODE_REVIEW_LOG_LEVEL": "WARNING",
}

for k, v in _SAFE_ENV.items():
    os.environ.setdefault(k, v)


@pytest.fixture(autouse=True, scope="session")
def _neutralise_settings():
    from security_code_review_agent.config import get_settings
    get_settings.cache_clear()
    for k, v in _SAFE_ENV.items():
        os.environ[k] = v
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_store():
    from security_code_review_agent.api.store import get_data_store
    get_data_store.cache_clear()
    yield
    get_data_store.cache_clear()


@pytest.fixture
def empty_state() -> dict:
    return {
        "scan_target": {},
        "sast_findings": [],
        "secrets_findings": [],
        "sca_findings": [],
        "fix_suggestions": [],
        "policy_verdict": {},
        "sbom": {},
        "pr_comments": [],
        "lifecycle_updates": [],
        "processing_errors": [],
    }


@pytest.fixture(scope="module")
def api_app():
    from security_code_review_agent.api.app import app
    return app
