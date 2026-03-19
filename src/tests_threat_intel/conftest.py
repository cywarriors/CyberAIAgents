"""
conftest.py – Shared fixtures for Threat Intelligence Agent tests.

Neutralises all external I/O so the suite runs without real API keys,
Kafka, Redis, or a database.
"""

from __future__ import annotations

import os
import importlib
import pytest

# ── Environment neutralization ──────────────────────────────────────────────
# Must happen before any agent module is imported.

_SAFE_ENV: dict[str, str] = {
    "THREAT_INTEL_ENV": "test",
    "THREAT_INTEL_LOG_LEVEL": "WARNING",
    # Kafka / Redis / DB – unreachable values so no real connection is attempted
    "THREAT_INTEL_KAFKA_BOOTSTRAP": "localhost:19092",
    "THREAT_INTEL_KAFKA_TOPIC": "test-threat-intelligence",
    "THREAT_INTEL_KAFKA_GROUP": "test-threat-intel-agent",
    "THREAT_INTEL_REDIS_URL": "redis://localhost:16379/9",
    "THREAT_INTEL_DATABASE_URL": "postgresql://test:test@localhost:15432/test_ti",
    # Feed URLs – empty so integrations fall back to mock data
    "THREAT_INTEL_OTX_API_KEY": "",
    "THREAT_INTEL_ABUSECH_URL": "",
    "THREAT_INTEL_CIRCL_TAXII_URL": "",
    "THREAT_INTEL_COMMERCIAL_FEED_URL": "",
    "THREAT_INTEL_COMMERCIAL_API_KEY": "",
    "THREAT_INTEL_ISAC_TAXII_URL": "",
    "THREAT_INTEL_ISAC_API_KEY": "",
    # Downstream endpoints – empty
    "THREAT_INTEL_SIEM_URL": "",
    "THREAT_INTEL_SIEM_API_KEY": "",
    "THREAT_INTEL_EDR_URL": "",
    "THREAT_INTEL_EDR_API_KEY": "",
    "THREAT_INTEL_FIREWALL_URL": "",
    "THREAT_INTEL_FIREWALL_API_KEY": "",
    "THREAT_INTEL_TICKETING_URL": "",
    "THREAT_INTEL_TICKETING_API_KEY": "",
    # Thresholds
    "THREAT_INTEL_CONFIDENCE_THRESHOLD": "70",
    "THREAT_INTEL_DISTRIBUTION_CONFIDENCE_MIN": "80",
}

for _k, _v in _SAFE_ENV.items():
    os.environ.setdefault(_k, _v)


# ── Lazy imports (after env is set) ─────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def _neutralise_settings():
    """Force pydantic settings to recompute with test env values."""
    try:
        cfg_mod = importlib.import_module("threat_intelligence_agent.config")
        if hasattr(cfg_mod, "get_settings"):
            cfg_mod.get_settings.cache_clear()
    except Exception:
        pass
    yield
    try:
        cfg_mod = importlib.import_module("threat_intelligence_agent.config")
        if hasattr(cfg_mod, "get_settings"):
            cfg_mod.get_settings.cache_clear()
    except Exception:
        pass


# ── InMemoryStore reset ──────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_store():
    """Reset the InMemoryStore singleton between every test."""
    try:
        dep_mod = importlib.import_module("threat_intelligence_agent.api.dependencies")
        store = dep_mod.InMemoryStore()
        # Reset to initial seeded state
        store._initialised = False  # type: ignore[attr-defined]
        store.__init__()  # type: ignore[misc]
    except Exception:
        pass
    yield
    try:
        dep_mod = importlib.import_module("threat_intelligence_agent.api.dependencies")
        store = dep_mod.InMemoryStore()
        store._initialised = False  # type: ignore[attr-defined]
        store.__init__()  # type: ignore[misc]
    except Exception:
        pass


# ── Empty state fixture ──────────────────────────────────────────────────────

@pytest.fixture()
def empty_state() -> dict:
    """Return a minimal ThreatIntelState-compatible dict."""
    return {
        "raw_intel": [],
        "normalized_objects": [],
        "deduplicated_iocs": [],
        "confidence_scores": [],
        "relevance_assessments": [],
        "attck_mappings": [],
        "briefs": [],
        "distribution_results": [],
        "feedback_results": [],
        "processing_errors": [],
    }


# ── FastAPI test client ──────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def api_app():
    """Return the FastAPI application instance."""
    from threat_intelligence_agent.api.app import app  # noqa: PLC0415
    return app
