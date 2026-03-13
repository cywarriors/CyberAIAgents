"""Named phishing scenarios for validation testing.

Each scenario provides pre-built email sets with expected outcomes.
Used by integration tests and acceptance tests per SRS-05.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tests_phishing.mocks.generators import (
    generate_bec_email,
    generate_clean_external_email,
    generate_clean_internal_email,
    generate_clean_with_attachment,
    generate_credential_harvest_email,
    generate_display_name_spoof_email,
    generate_lookalike_domain_email,
    generate_malware_delivery_email,
    generate_new_domain_email,
    generate_spear_phishing_vip,
    generate_url_phishing_email,
)


@dataclass
class PhishingScenario:
    name: str
    description: str
    emails: list[dict[str, Any]] = field(default_factory=list)
    expected_verdict: str = "malicious"
    expected_action: str = "block"
    expected_min_risk_score: float = 0.0
    expected_threat_types: list[str] = field(default_factory=list)
    should_quarantine: bool = False
    should_block: bool = False
    should_allow: bool = False


SCENARIOS: list[PhishingScenario] = [
    PhishingScenario(
        name="Credential Harvesting",
        description="Phishing email with fake login page URL.",
        emails=[generate_credential_harvest_email()],
        expected_verdict="malicious",
        expected_action="block",
        expected_min_risk_score=50.0,
        expected_threat_types=["credential_harvest"],
        should_block=True,
    ),
    PhishingScenario(
        name="Business Email Compromise",
        description="BEC impersonation targeting CFO.",
        emails=[generate_bec_email()],
        expected_verdict="malicious",
        expected_action="block",
        expected_min_risk_score=30.0,
        expected_threat_types=["bec", "financial_fraud"],
        should_block=True,
    ),
    PhishingScenario(
        name="Malware Delivery",
        description="Email with macro-enabled malicious attachment.",
        emails=[generate_malware_delivery_email()],
        expected_verdict="malicious",
        expected_action="quarantine",
        expected_min_risk_score=30.0,
        expected_threat_types=["malware_delivery"],
        should_quarantine=True,
    ),
    PhishingScenario(
        name="Lookalike Domain",
        description="Email from visually similar domain.",
        emails=[generate_lookalike_domain_email()],
        expected_verdict="suspicious",
        expected_action="warn",
        expected_min_risk_score=20.0,
        expected_threat_types=["impersonation"],
        should_quarantine=True,
    ),
    PhishingScenario(
        name="URL Phishing with Shorteners",
        description="Email containing shortened and suspicious URLs.",
        emails=[generate_url_phishing_email()],
        expected_verdict="suspicious",
        expected_action="quarantine",
        expected_min_risk_score=30.0,
        should_quarantine=True,
    ),
    PhishingScenario(
        name="VIP Spear Phishing",
        description="Targeted attack on C-suite executive.",
        emails=[generate_spear_phishing_vip()],
        expected_verdict="malicious",
        expected_action="block",
        expected_min_risk_score=50.0,
        should_block=True,
    ),
    PhishingScenario(
        name="Clean Internal Email",
        description="Normal internal communication.",
        emails=[generate_clean_internal_email()],
        expected_verdict="clean",
        expected_action="allow",
        expected_min_risk_score=0.0,
        should_allow=True,
    ),
    PhishingScenario(
        name="Clean External Email",
        description="Legitimate external email with proper auth.",
        emails=[generate_clean_external_email()],
        expected_verdict="clean",
        expected_action="allow",
        expected_min_risk_score=0.0,
        should_allow=True,
    ),
    PhishingScenario(
        name="Clean with Attachment",
        description="Legitimate email with safe attachment.",
        emails=[generate_clean_with_attachment()],
        expected_verdict="clean",
        expected_action="allow",
        expected_min_risk_score=0.0,
        should_allow=True,
    ),
    PhishingScenario(
        name="New Domain Sender",
        description="Email from a recently registered domain.",
        emails=[generate_new_domain_email()],
        expected_verdict="suspicious",
        expected_action="allow",
        expected_min_risk_score=10.0,
        should_allow=True,
    ),
    PhishingScenario(
        name="Display Name Spoof",
        description="Sender display name spoofing internal employee.",
        emails=[generate_display_name_spoof_email()],
        expected_verdict="malicious",
        expected_action="block",
        expected_min_risk_score=30.0,
        should_block=True,
    ),
]

SCENARIO_BY_NAME: dict[str, PhishingScenario] = {s.name: s for s in SCENARIOS}
