"""ATT&CK coverage heatmap endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from threat_detection_agent.api.dependencies import get_store
from threat_detection_agent.api.schemas import CoverageResponse, TechniqueCoverage

router = APIRouter(prefix="/api/v1/coverage", tags=["coverage"])

# Subset of ATT&CK techniques for coverage mapping
_ATTACK_TECHNIQUES = [
    ("T1110", "Brute Force", "Credential Access"),
    ("T1078", "Valid Accounts", "Initial Access"),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    ("T1071.004", "DNS Tunnelling", "Command and Control"),
    ("T1078.003", "Cloud Accounts", "Privilege Escalation"),
    ("T1021", "Remote Services", "Lateral Movement"),
    ("T1059", "Command and Scripting Interpreter", "Execution"),
    ("T1566", "Phishing", "Initial Access"),
    ("T1053", "Scheduled Task/Job", "Persistence"),
    ("T1098", "Account Manipulation", "Persistence"),
    ("T1027", "Obfuscated Files", "Defense Evasion"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
]


@router.get("/attack", response_model=CoverageResponse)
async def get_attack_coverage():
    store = get_store()
    techniques: list[TechniqueCoverage] = []

    # Collect technique IDs covered by alerts and rules
    covered_ids: set[str] = set()
    for alert in store.alerts.values():
        for tid in alert.get("mitre_technique_ids", []):
            covered_ids.add(tid)
    for rule in store.rules.values():
        tid = rule.get("mitre_technique_id", "")
        if tid:
            covered_ids.add(tid)

    for tid, name, tactic in _ATTACK_TECHNIQUES:
        rule_count = sum(
            1
            for r in store.rules.values()
            if r.get("mitre_technique_id") == tid
        )
        alert_count = sum(
            1
            for a in store.alerts.values()
            if tid in a.get("mitre_technique_ids", [])
        )
        covered = tid in covered_ids
        techniques.append(
            TechniqueCoverage(
                technique_id=tid,
                technique_name=name,
                tactic=tactic,
                rule_count=rule_count,
                alert_count=alert_count,
                covered=covered,
            )
        )

    covered_count = sum(1 for t in techniques if t.covered)
    return CoverageResponse(
        total_techniques=len(techniques),
        covered_techniques=covered_count,
        coverage_percentage=round(
            (covered_count / len(techniques) * 100) if techniques else 0, 1
        ),
        techniques=techniques,
    )
