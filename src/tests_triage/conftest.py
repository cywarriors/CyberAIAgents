"""Shared pytest fixtures for the Incident Triage Agent test suite."""

from __future__ import annotations

import os
from typing import Any

import pytest

# Ensure integration clients never hit real endpoints during tests
os.environ.setdefault("SIEM_API_KEY", "")
os.environ.setdefault("EDR_API_KEY", "")
os.environ.setdefault("TICKETING_API_KEY", "")
os.environ.setdefault("MESSAGING_WEBHOOK_URL", "")
os.environ.setdefault("THREAT_INTEL_API_KEY", "")
os.environ.setdefault("CMDB_API_KEY", "")
os.environ.setdefault("IDENTITY_API_KEY", "")
os.environ.setdefault("VULN_API_KEY", "")
os.environ.setdefault("LLM_API_KEY", "")
os.environ.setdefault("AGENT_ENV", "testing")

from tests_triage.mocks.generators import (
    generate_all_attack_alerts,
    generate_benign_auth_alert,
    generate_benign_network_alert,
    generate_benign_process_alert,
    generate_brute_force_alert,
    generate_credential_stuffing_campaign,
    generate_data_exfil_alert,
    generate_dns_tunnelling_alert,
    generate_impossible_travel_alert,
    generate_insider_threat_alert,
    generate_lateral_movement_alert,
    generate_malware_execution_alert,
    generate_mixed_alert_batch,
    generate_multi_stage_intrusion,
    generate_phishing_alert,
    generate_privilege_escalation_alert,
    generate_ransomware_alert,
)


# ---------------------------------------------------------------------------
# Alert fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def benign_alerts() -> list[dict[str, Any]]:
    return [
        generate_benign_auth_alert(),
        generate_benign_network_alert(),
        generate_benign_process_alert(),
    ]


@pytest.fixture()
def attack_alerts() -> list[dict[str, Any]]:
    return generate_all_attack_alerts()


@pytest.fixture()
def mixed_batch() -> list[dict[str, Any]]:
    return generate_mixed_alert_batch(total=50, attack_ratio=0.3, seed=123)


@pytest.fixture()
def brute_force_alert() -> dict[str, Any]:
    return generate_brute_force_alert()


@pytest.fixture()
def impossible_travel_alert() -> dict[str, Any]:
    return generate_impossible_travel_alert()


@pytest.fixture()
def data_exfil_alert() -> dict[str, Any]:
    return generate_data_exfil_alert()


@pytest.fixture()
def dns_tunnelling_alert() -> dict[str, Any]:
    return generate_dns_tunnelling_alert()


@pytest.fixture()
def privilege_escalation_alert() -> dict[str, Any]:
    return generate_privilege_escalation_alert()


@pytest.fixture()
def lateral_movement_alert() -> dict[str, Any]:
    return generate_lateral_movement_alert()


@pytest.fixture()
def malware_execution_alert() -> dict[str, Any]:
    return generate_malware_execution_alert()


@pytest.fixture()
def insider_threat_alert() -> dict[str, Any]:
    return generate_insider_threat_alert()


@pytest.fixture()
def phishing_alert() -> dict[str, Any]:
    return generate_phishing_alert()


@pytest.fixture()
def ransomware_alert() -> dict[str, Any]:
    return generate_ransomware_alert()


# ---------------------------------------------------------------------------
# Multi-alert fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def multi_stage_intrusion() -> list[dict[str, Any]]:
    return generate_multi_stage_intrusion()


@pytest.fixture()
def credential_stuffing_campaign() -> list[dict[str, Any]]:
    return generate_credential_stuffing_campaign()


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_state() -> dict[str, Any]:
    """Minimal empty triage state for unit testing nodes."""
    return {
        "triage_batch_id": [],
        "raw_alerts": [],
        "entity_context": [],
        "correlations": [],
        "priority_scores": [],
        "classifications": [],
        "triage_summaries": [],
        "recommended_actions": [],
        "incident_timeline": [],
        "triaged_incidents": [],
        "case_ids": [],
        "feedback_queue": [],
        "errors": [],
    }
