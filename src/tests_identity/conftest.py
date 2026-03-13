"""Shared pytest fixtures for the Identity & Access Monitoring Agent test suite."""

from __future__ import annotations

import os
from typing import Any

import pytest

# Ensure integration clients never hit real endpoints during tests
os.environ.setdefault("IDENTITY_AGENT_ENV", "testing")
os.environ.setdefault("IDENTITY_IDP_API_URL", "")
os.environ.setdefault("IDENTITY_MFA_API_URL", "")
os.environ.setdefault("IDENTITY_EDR_API_URL", "")
os.environ.setdefault("IDENTITY_CASB_API_URL", "")
os.environ.setdefault("IDENTITY_SIEM_API_URL", "")
os.environ.setdefault("IDENTITY_TICKETING_API_URL", "")
os.environ.setdefault("IDENTITY_GEOIP_API_URL", "")
os.environ.setdefault("IDENTITY_MESSAGING_WEBHOOK_URL", "")
os.environ.setdefault("IDENTITY_KAFKA_BOOTSTRAP_SERVERS", "")
os.environ.setdefault("IDENTITY_VPN_ALLOWED_IPS", "10.0.0.100")

from tests_identity.mocks.generators import (
    generate_normal_auth_events,
    generate_brute_force_events,
    generate_impossible_travel_events,
    generate_mfa_fatigue_events,
    generate_off_hours_events,
    generate_new_device_events,
    generate_high_risk_role_changes,
    generate_self_escalation_role_changes,
    generate_sod_violating_role_changes,
    generate_normal_role_changes,
    generate_lockout_events,
    generate_mfa_bypass_events,
    generate_mixed_auth_batch,
    generate_mixed_role_batch,
)

# ---------------------------------------------------------------------------
# Auth event fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def normal_auth_events() -> list[dict[str, Any]]:
    return generate_normal_auth_events()


@pytest.fixture()
def brute_force_events() -> list[dict[str, Any]]:
    return generate_brute_force_events()


@pytest.fixture()
def impossible_travel_events() -> list[dict[str, Any]]:
    return generate_impossible_travel_events()


@pytest.fixture()
def mfa_fatigue_events() -> list[dict[str, Any]]:
    return generate_mfa_fatigue_events()


@pytest.fixture()
def off_hours_events() -> list[dict[str, Any]]:
    return generate_off_hours_events()


@pytest.fixture()
def new_device_events() -> list[dict[str, Any]]:
    return generate_new_device_events()


@pytest.fixture()
def lockout_events() -> list[dict[str, Any]]:
    return generate_lockout_events()


@pytest.fixture()
def mfa_bypass_events() -> list[dict[str, Any]]:
    return generate_mfa_bypass_events()


@pytest.fixture()
def mixed_auth_batch() -> list[dict[str, Any]]:
    return generate_mixed_auth_batch()


# ---------------------------------------------------------------------------
# Role change fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def normal_role_changes() -> list[dict[str, Any]]:
    return generate_normal_role_changes()


@pytest.fixture()
def high_risk_role_changes() -> list[dict[str, Any]]:
    return generate_high_risk_role_changes()


@pytest.fixture()
def self_escalation_role_changes() -> list[dict[str, Any]]:
    return generate_self_escalation_role_changes()


@pytest.fixture()
def sod_violating_role_changes() -> list[dict[str, Any]]:
    return generate_sod_violating_role_changes()


@pytest.fixture()
def mixed_role_batch() -> list[dict[str, Any]]:
    return generate_mixed_role_batch()


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_state() -> dict[str, Any]:
    """Minimal empty identity risk state for unit testing nodes."""
    return {
        "batch_id": "",
        "raw_auth_events": [],
        "raw_role_changes": [],
        "session_profiles": [],
        "session_anomalies": [],
        "privilege_alerts": [],
        "sod_violations": [],
        "takeover_signals": [],
        "risk_scores": [],
        "recommendations": [],
        "alerts": [],
        "feedback_queue": [],
        "errors": [],
    }
