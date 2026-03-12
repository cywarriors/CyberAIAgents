"""Named triage scenarios for incident triage validation.

Each scenario provides pre-built alert sets with expected outcomes:
- Expected priority (P1-P4)
- Expected classification
- Expected number of correlation groups
- Whether the scenario should produce recommended actions

Used by integration tests and acceptance tests per SRS-02 §14.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tests_triage.mocks.generators import (
    generate_brute_force_alert,
    generate_credential_stuffing_campaign,
    generate_data_exfil_alert,
    generate_dns_tunnelling_alert,
    generate_impossible_travel_alert,
    generate_insider_threat_alert,
    generate_lateral_movement_alert,
    generate_malware_execution_alert,
    generate_multi_stage_intrusion,
    generate_phishing_alert,
    generate_privilege_escalation_alert,
    generate_ransomware_alert,
)


@dataclass
class TriageScenario:
    name: str
    description: str
    mitre_ids: list[str]
    alerts: list[dict[str, Any]] = field(default_factory=list)
    expected_priority: str = "P2"  # P1, P2, P3, P4
    expected_classification: str = "unknown"
    expected_min_correlation_groups: int = 1
    expected_has_recommendations: bool = True


# ---------------------------------------------------------------------------
# Pre-built scenarios
# ---------------------------------------------------------------------------

SCENARIOS: list[TriageScenario] = [
    # ------- Single-alert scenarios -------
    TriageScenario(
        name="Brute Force Attack",
        description="Single brute-force alert from failed-login spike.",
        mitre_ids=["T1110"],
        alerts=[generate_brute_force_alert()],
        expected_priority="P3",
        expected_classification="credential_abuse",
        expected_min_correlation_groups=1,
    ),
    TriageScenario(
        name="Impossible Travel Login",
        description="User logs in from a geographically impossible location.",
        mitre_ids=["T1078"],
        alerts=[generate_impossible_travel_alert()],
        expected_priority="P3",
        expected_classification="credential_abuse",
        expected_min_correlation_groups=1,
    ),
    TriageScenario(
        name="Data Exfiltration",
        description="High-volume outbound transfer to external IP from internal host.",
        mitre_ids=["T1041"],
        alerts=[generate_data_exfil_alert()],
        expected_priority="P3",
        expected_classification="data_exfiltration",
        expected_min_correlation_groups=1,
    ),
    TriageScenario(
        name="DNS Tunnelling C2",
        description="Suspicious DNS query pattern matching C2 communication.",
        mitre_ids=["T1071.004"],
        alerts=[generate_dns_tunnelling_alert()],
        expected_priority="P4",
        expected_classification="command_and_control",
        expected_min_correlation_groups=1,
    ),
    TriageScenario(
        name="Cloud Privilege Escalation",
        description="Non-admin user assumes admin role in production cloud.",
        mitre_ids=["T1078.003"],
        alerts=[generate_privilege_escalation_alert()],
        expected_priority="P3",
        expected_classification="privilege_escalation",
        expected_min_correlation_groups=1,
    ),
    TriageScenario(
        name="Lateral Movement via RDP",
        description="Internal RDP session between hosts.",
        mitre_ids=["T1021"],
        alerts=[generate_lateral_movement_alert()],
        expected_priority="P4",
        expected_classification="lateral_movement",
        expected_min_correlation_groups=1,
    ),
    TriageScenario(
        name="Encoded PowerShell Execution",
        description="Encoded PowerShell command execution on endpoint.",
        mitre_ids=["T1059"],
        alerts=[generate_malware_execution_alert()],
        expected_priority="P3",
        expected_classification="malware",
        expected_min_correlation_groups=1,
    ),
    TriageScenario(
        name="Insider Threat After-Hours Access",
        description="Privileged user accessing critical host outside business hours.",
        mitre_ids=["T1078"],
        alerts=[generate_insider_threat_alert()],
        expected_priority="P2",
        expected_classification="insider_threat",
        expected_min_correlation_groups=1,
    ),
    TriageScenario(
        name="Phishing Link Click",
        description="User clicks credential-harvesting link from phishing email.",
        mitre_ids=["T1566"],
        alerts=[generate_phishing_alert()],
        expected_priority="P3",
        expected_classification="phishing",
        expected_min_correlation_groups=1,
    ),
    TriageScenario(
        name="Ransomware Mass Encryption",
        description="Mass file encryption detected on critical infrastructure host.",
        mitre_ids=["T1486"],
        alerts=[generate_ransomware_alert()],
        expected_priority="P2",
        expected_classification="ransomware",
        expected_min_correlation_groups=1,
    ),
    # ------- Multi-alert / correlation scenarios -------
    TriageScenario(
        name="Multi-Stage Intrusion Chain",
        description=(
            "Full kill chain: phishing → credential theft → lateral movement → "
            "data exfiltration. Alerts share user/host entities and should "
            "correlate into a single incident."
        ),
        mitre_ids=["T1566", "T1110", "T1021", "T1041"],
        alerts=generate_multi_stage_intrusion(),
        expected_priority="P1",
        expected_classification="data_exfiltration",
        expected_min_correlation_groups=1,
        expected_has_recommendations=True,
    ),
    TriageScenario(
        name="Credential Stuffing Campaign",
        description=(
            "Multiple users targeted from same source IP in rapid succession. "
            "Alerts share source IP and should correlate."
        ),
        mitre_ids=["T1110"],
        alerts=generate_credential_stuffing_campaign(),
        expected_priority="P3",
        expected_classification="credential_abuse",
        expected_min_correlation_groups=1,
        expected_has_recommendations=True,
    ),
]

# Convenience lookups
SCENARIO_BY_NAME: dict[str, TriageScenario] = {s.name: s for s in SCENARIOS}
