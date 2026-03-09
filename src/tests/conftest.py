"""Shared pytest fixtures for the Threat Detection Agent test suite."""

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
os.environ.setdefault("AGENT_ENV", "testing")

from tests.mocks.generators import (
    generate_all_attack_scenarios,
    generate_benign_auth_event,
    generate_benign_dns_event,
    generate_benign_network_event,
    generate_benign_process_event,
    generate_brute_force_event,
    generate_data_exfil_event,
    generate_dns_tunnelling_event,
    generate_impossible_travel_event,
    generate_malware_execution_event,
    generate_mixed_batch,
    generate_privilege_escalation_event,
)
from threat_detection_agent.nodes.deduplicate import reset_dedup_cache


@pytest.fixture(autouse=True)
def _clean_dedup_cache():
    """Reset the in-process dedup cache before every test."""
    reset_dedup_cache()
    yield
    reset_dedup_cache()


@pytest.fixture()
def benign_events() -> list[dict[str, Any]]:
    return [
        generate_benign_auth_event(),
        generate_benign_network_event(),
        generate_benign_dns_event(),
        generate_benign_process_event(),
    ]


@pytest.fixture()
def attack_events() -> list[dict[str, Any]]:
    return generate_all_attack_scenarios()


@pytest.fixture()
def mixed_batch() -> list[dict[str, Any]]:
    return generate_mixed_batch(total=50, attack_ratio=0.3, seed=123)


@pytest.fixture()
def brute_force_event() -> dict[str, Any]:
    return generate_brute_force_event()


@pytest.fixture()
def impossible_travel_event() -> dict[str, Any]:
    return generate_impossible_travel_event()


@pytest.fixture()
def data_exfil_event() -> dict[str, Any]:
    return generate_data_exfil_event()


@pytest.fixture()
def dns_tunnelling_event() -> dict[str, Any]:
    return generate_dns_tunnelling_event()


@pytest.fixture()
def privilege_escalation_event() -> dict[str, Any]:
    return generate_privilege_escalation_event()


@pytest.fixture()
def malware_execution_event() -> dict[str, Any]:
    return generate_malware_execution_event()
