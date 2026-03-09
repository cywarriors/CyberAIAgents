"""Named attack scenarios for detection validation (§14 – Detection Tests).

Each scenario describes an adversary playbook as a sequence of events.
The test harness feeds the sequence into the pipeline and asserts
that the expected alert(s) appear.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tests.mocks.generators import (
    generate_brute_force_event,
    generate_data_exfil_event,
    generate_dns_tunnelling_event,
    generate_impossible_travel_event,
    generate_lateral_movement_event,
    generate_malware_execution_event,
    generate_privilege_escalation_event,
)


@dataclass
class AttackScenario:
    name: str
    description: str
    mitre_ids: list[str]
    events: list[dict[str, Any]] = field(default_factory=list)
    expected_rule_ids: list[str] = field(default_factory=list)
    expected_min_severity: str = "Medium"


# ---------------------------------------------------------------------------
# Pre-built scenarios
# ---------------------------------------------------------------------------

SCENARIOS: list[AttackScenario] = [
    AttackScenario(
        name="Brute Force Attack",
        description="Adversary attempts credential stuffing via multiple failed logins.",
        mitre_ids=["T1110"],
        events=[generate_brute_force_event() for _ in range(3)],
        expected_rule_ids=["RULE-AUTH-001"],
        expected_min_severity="High",
    ),
    AttackScenario(
        name="Impossible Travel Login",
        description="Valid user logs in from a geographically impossible location.",
        mitre_ids=["T1078"],
        events=[generate_impossible_travel_event()],
        expected_rule_ids=["RULE-AUTH-002"],
        expected_min_severity="High",
    ),
    AttackScenario(
        name="Data Exfiltration",
        description="Insider or compromised host exfiltrates large data volumes.",
        mitre_ids=["T1041"],
        events=[generate_data_exfil_event()],
        expected_rule_ids=["RULE-NET-001"],
        expected_min_severity="Critical",
    ),
    AttackScenario(
        name="DNS Tunnelling C2",
        description="Malware communicates via high-volume DNS queries to suspicious domain.",
        mitre_ids=["T1071.004"],
        events=[generate_dns_tunnelling_event()],
        expected_rule_ids=["RULE-DNS-001"],
        expected_min_severity="High",
    ),
    AttackScenario(
        name="Cloud Privilege Escalation",
        description="User assumes an admin role in a production cloud account.",
        mitre_ids=["T1078.003"],
        events=[generate_privilege_escalation_event()],
        expected_rule_ids=["RULE-IAM-001"],
        expected_min_severity="Critical",
    ),
    AttackScenario(
        name="Lateral Movement via RDP",
        description="Attacker pivots between hosts using internal remote desktop.",
        mitre_ids=["T1021"],
        events=[generate_lateral_movement_event()],
        expected_rule_ids=["RULE-NET-002"],
        expected_min_severity="Medium",
    ),
    AttackScenario(
        name="Encoded PowerShell Execution",
        description="Malware drops and runs base64-encoded PowerShell payload.",
        mitre_ids=["T1059"],
        events=[generate_malware_execution_event()],
        expected_rule_ids=["RULE-END-001"],
        expected_min_severity="High",
    ),
]
