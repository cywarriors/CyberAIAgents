"""MapTTPsNode — map observed behavior to MITRE ATT&CK framework."""
from __future__ import annotations
import structlog

log = structlog.get_logger()

# Simplified ATT&CK mapping: interaction_type → [(technique_id, tactic, name)]
_ATTACK_MAP: dict[str, list[tuple[str, str, str]]] = {
    "scan": [
        ("T1046", "Discovery", "Network Service Discovery"),
        ("T1595", "Reconnaissance", "Active Scanning"),
    ],
    "probe": [
        ("T1592", "Reconnaissance", "Gather Victim Host Information"),
        ("T1046", "Discovery", "Network Service Discovery"),
    ],
    "exploit": [
        ("T1190", "Initial Access", "Exploit Public-Facing Application"),
        ("T1059", "Execution", "Command and Scripting Interpreter"),
    ],
    "lateral": [
        ("T1021", "Lateral Movement", "Remote Services"),
        ("T1550", "Lateral Movement", "Use Alternate Authentication Material"),
    ],
    "credential_use": [
        ("T1110", "Credential Access", "Brute Force"),
        ("T1078", "Defense Evasion", "Valid Accounts"),
    ],
    "file_access": [
        ("T1083", "Discovery", "File and Directory Discovery"),
        ("T1005", "Collection", "Data from Local System"),
    ],
    "unknown": [
        ("T1040", "Credential Access", "Network Sniffing"),
    ],
}


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def map_ttps(state) -> dict:
    """Map classified interactions to MITRE ATT&CK TTPs."""
    classified = list(_s(state, "classified_interactions", []))
    mappings = []
    for interaction in classified:
        itype = interaction.get("interaction_type", "unknown")
        techniques = _ATTACK_MAP.get(itype, _ATTACK_MAP["unknown"])
        for tech_id, tactic, name in techniques:
            mappings.append({
                "interaction_id": interaction.get("interaction_id", ""),
                "source_ip": interaction.get("source_ip", ""),
                "interaction_type": itype,
                "technique_id": tech_id,
                "tactic": tactic,
                "technique_name": name,
                "decoy_id": interaction.get("decoy_id", ""),
            })

    log.info("map_ttps.done", mappings=len(mappings))
    return {"ttp_mappings": mappings}
