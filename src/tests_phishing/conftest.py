"""Shared pytest fixtures for the Phishing Defense Agent test suite."""

from __future__ import annotations

import os
from typing import Any

import pytest

# Ensure integration clients never hit real endpoints during tests
os.environ.setdefault("PHISHING_AGENT_ENV", "testing")
os.environ.setdefault("PHISHING_EMAIL_GATEWAY_URL", "")
os.environ.setdefault("PHISHING_SANDBOX_API_URL", "")
os.environ.setdefault("PHISHING_THREAT_INTEL_API_URL", "")
os.environ.setdefault("PHISHING_SIEM_API_URL", "")
os.environ.setdefault("PHISHING_TICKETING_API_URL", "")
os.environ.setdefault("PHISHING_MESSAGING_WEBHOOK_URL", "")
os.environ.setdefault("PHISHING_KAFKA_BOOTSTRAP_SERVERS", "")

from tests_phishing.mocks.generators import (
    generate_all_clean_emails,
    generate_all_phishing_emails,
    generate_bec_email,
    generate_clean_external_email,
    generate_clean_internal_email,
    generate_clean_with_attachment,
    generate_credential_harvest_email,
    generate_display_name_spoof_email,
    generate_lookalike_domain_email,
    generate_malware_delivery_email,
    generate_mixed_email_batch,
    generate_new_domain_email,
    generate_spear_phishing_vip,
    generate_url_phishing_email,
)

# ---------------------------------------------------------------------------
# Email fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def clean_emails() -> list[dict[str, Any]]:
    return generate_all_clean_emails()


@pytest.fixture()
def phishing_emails() -> list[dict[str, Any]]:
    return generate_all_phishing_emails()


@pytest.fixture()
def mixed_batch() -> list[dict[str, Any]]:
    return generate_mixed_email_batch(total=50, phishing_ratio=0.3, seed=123)


@pytest.fixture()
def credential_harvest_email() -> dict[str, Any]:
    return generate_credential_harvest_email()


@pytest.fixture()
def bec_email() -> dict[str, Any]:
    return generate_bec_email()


@pytest.fixture()
def malware_delivery_email() -> dict[str, Any]:
    return generate_malware_delivery_email()


@pytest.fixture()
def lookalike_domain_email() -> dict[str, Any]:
    return generate_lookalike_domain_email()


@pytest.fixture()
def url_phishing_email() -> dict[str, Any]:
    return generate_url_phishing_email()


@pytest.fixture()
def spear_phishing_vip_email() -> dict[str, Any]:
    return generate_spear_phishing_vip()


@pytest.fixture()
def new_domain_email() -> dict[str, Any]:
    return generate_new_domain_email()


@pytest.fixture()
def display_name_spoof_email() -> dict[str, Any]:
    return generate_display_name_spoof_email()


@pytest.fixture()
def clean_internal_email() -> dict[str, Any]:
    return generate_clean_internal_email()


@pytest.fixture()
def clean_external_email() -> dict[str, Any]:
    return generate_clean_external_email()


@pytest.fixture()
def clean_attachment_email() -> dict[str, Any]:
    return generate_clean_with_attachment()


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_state() -> dict[str, Any]:
    """Minimal empty phishing verdict state for unit testing nodes."""
    return {
        "raw_emails": [],
        "email_features": [],
        "auth_results": [],
        "content_signals": [],
        "sandbox_results": [],
        "risk_scores": [],
        "verdicts": [],
        "extracted_iocs": [],
        "notifications": [],
        "feedback_queue": [],
        "errors": [],
    }
