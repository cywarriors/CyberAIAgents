"""Baseline detection rules mapped to MITRE ATT&CK technique IDs."""

from __future__ import annotations

from typing import Any, Callable


def _brute_force_rule(event: dict[str, Any]) -> dict | None:
    """T1110 – Brute Force: multiple failed authentications."""
    if event.get("category") != "authentication":
        return None
    action = str(event.get("action", "")).lower()
    outcome = str(event.get("outcome", "")).lower()
    attempts = int(event.get("raw_snippet", {}).get("attempt_count", 0))
    if ("fail" in action or "fail" in outcome) and attempts >= 5:
        return {
            "rule_id": "RULE-AUTH-001",
            "rule_name": "Brute Force – Excessive Failed Logins",
            "mitre_technique_id": "T1110",
            "mitre_tactic": "Credential Access",
            "severity": "High",
            "matched_event_ids": [event["event_id"]],
            "description": (
                f"User '{event.get('user_name')}' had {attempts} failed login attempts "
                f"from {event.get('src_ip')}"
            ),
            "raw_evidence": [event.get("raw_snippet", {})],
        }
    return None


def _impossible_travel_rule(event: dict[str, Any]) -> dict | None:
    """T1078 – Valid Accounts: login from unexpected geolocation."""
    if event.get("category") != "authentication":
        return None
    geo = event.get("raw_snippet", {}).get("geo_country")
    expected = event.get("raw_snippet", {}).get("expected_country")
    if geo and expected and geo != expected:
        return {
            "rule_id": "RULE-AUTH-002",
            "rule_name": "Impossible Travel – Anomalous Geolocation Login",
            "mitre_technique_id": "T1078",
            "mitre_tactic": "Initial Access",
            "severity": "High",
            "matched_event_ids": [event["event_id"]],
            "description": (
                f"User '{event.get('user_name')}' logged in from {geo} "
                f"(expected {expected})"
            ),
            "raw_evidence": [event.get("raw_snippet", {})],
        }
    return None


def _data_exfil_rule(event: dict[str, Any]) -> dict | None:
    """T1041 – Exfiltration Over C2 Channel: large outbound transfer."""
    bytes_out = event.get("raw_snippet", {}).get("bytes_out")
    if bytes_out is not None and int(bytes_out) > 500_000:
        return {
            "rule_id": "RULE-NET-001",
            "rule_name": "Potential Data Exfiltration – Large Outbound Transfer",
            "mitre_technique_id": "T1041",
            "mitre_tactic": "Exfiltration",
            "severity": "Critical",
            "matched_event_ids": [event["event_id"]],
            "description": (
                f"Host '{event.get('host_name')}' sent {bytes_out} bytes "
                f"to {event.get('dst_ip')}"
            ),
            "raw_evidence": [event.get("raw_snippet", {})],
        }
    return None


def _dns_tunnelling_rule(event: dict[str, Any]) -> dict | None:
    """T1071.004 – Application Layer Protocol: DNS tunnelling."""
    if event.get("category") != "dns":
        return None
    query_count = int(event.get("raw_snippet", {}).get("query_count", 0))
    domain = event.get("domain", "")
    if query_count > 100 or (domain and len(domain) > 60):
        return {
            "rule_id": "RULE-DNS-001",
            "rule_name": "DNS Tunnelling Suspect – High Query Volume / Long Domain",
            "mitre_technique_id": "T1071.004",
            "mitre_tactic": "Command and Control",
            "severity": "High",
            "matched_event_ids": [event["event_id"]],
            "description": (
                f"Host '{event.get('host_name')}' – {query_count} DNS queries, "
                f"domain length {len(domain)}"
            ),
            "raw_evidence": [event.get("raw_snippet", {})],
        }
    return None


def _privilege_escalation_rule(event: dict[str, Any]) -> dict | None:
    """T1078.003 – Valid Accounts: Cloud – unexpected admin role assumption."""
    if event.get("category") not in ("iam", "cloud_audit"):
        return None
    action = str(event.get("action", "")).lower()
    if "assume" in action or "elevat" in action or "grant" in action:
        return {
            "rule_id": "RULE-IAM-001",
            "rule_name": "Privilege Escalation – Unexpected Role Change",
            "mitre_technique_id": "T1078.003",
            "mitre_tactic": "Privilege Escalation",
            "severity": "Critical",
            "matched_event_ids": [event["event_id"]],
            "description": (
                f"User '{event.get('user_name')}' performed '{event.get('action')}' "
                f"on {event.get('host_name', 'cloud resource')}"
            ),
            "raw_evidence": [event.get("raw_snippet", {})],
        }
    return None


def _lateral_movement_rule(event: dict[str, Any]) -> dict | None:
    """T1021 – Remote Services: unusual internal RDP / SSH."""
    if event.get("category") != "network":
        return None
    action = str(event.get("action", "")).lower()
    if "rdp" in action or "ssh" in action:
        if event.get("raw_snippet", {}).get("internal", False):
            return {
                "rule_id": "RULE-NET-002",
                "rule_name": "Lateral Movement – Internal Remote Service",
                "mitre_technique_id": "T1021",
                "mitre_tactic": "Lateral Movement",
                "severity": "Medium",
                "matched_event_ids": [event["event_id"]],
                "description": (
                    f"Internal remote session ({action}) from {event.get('src_ip')} "
                    f"to {event.get('dst_ip')}"
                ),
                "raw_evidence": [event.get("raw_snippet", {})],
            }
    return None


def _malware_execution_rule(event: dict[str, Any]) -> dict | None:
    """T1059 – Command and Scripting Interpreter: suspicious process."""
    if event.get("category") not in ("process", "endpoint"):
        return None
    process = str(event.get("process_name", "")).lower()
    suspicious = {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "certutil.exe"}
    if process in suspicious:
        encoded = event.get("raw_snippet", {}).get("command_line", "")
        if "-enc" in str(encoded).lower() or "-e " in str(encoded).lower() or "base64" in str(encoded).lower():
            return {
                "rule_id": "RULE-END-001",
                "rule_name": "Suspicious Encoded Command Execution",
                "mitre_technique_id": "T1059",
                "mitre_tactic": "Execution",
                "severity": "High",
                "matched_event_ids": [event["event_id"]],
                "description": (
                    f"Process '{process}' launched with encoded arguments on "
                    f"host '{event.get('host_name')}'"
                ),
                "raw_evidence": [event.get("raw_snippet", {})],
            }
    return None


# ---------------------------------------------------------------------------
# Public registry of all baseline rules
# ---------------------------------------------------------------------------

BASELINE_RULES: list[Callable[[dict[str, Any]], dict | None]] = [
    _brute_force_rule,
    _impossible_travel_rule,
    _data_exfil_rule,
    _dns_tunnelling_rule,
    _privilege_escalation_rule,
    _lateral_movement_rule,
    _malware_execution_rule,
]
