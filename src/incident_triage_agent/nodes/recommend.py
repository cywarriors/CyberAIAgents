"""RecommendActionsNode – suggest prioritised investigative steps (§12.2, FR-07)."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Playbook catalog: MITRE technique → recommended actions
_PLAYBOOK_ACTIONS: dict[str, list[dict[str, str]]] = {
    "T1110": [
        {"title": "Lock affected user account", "type": "contain", "desc": "Temporarily lock the account pending investigation to prevent further brute-force attempts."},
        {"title": "Review authentication logs", "type": "investigate", "desc": "Examine login history for the affected user across all identity providers."},
        {"title": "Check for credential reuse", "type": "investigate", "desc": "Verify if compromised credentials were reused on other services."},
        {"title": "Enable MFA enforcement", "type": "contain", "desc": "Ensure multi-factor authentication is required for the affected account."},
    ],
    "T1078": [
        {"title": "Verify user identity", "type": "investigate", "desc": "Contact the user to confirm whether the login was legitimate."},
        {"title": "Review session activity", "type": "investigate", "desc": "Examine all actions performed during the suspicious session."},
        {"title": "Revoke active sessions", "type": "contain", "desc": "Invalidate all active sessions for the affected user."},
    ],
    "T1041": [
        {"title": "Block destination IP", "type": "contain", "desc": "Add the exfiltration destination to the firewall block list."},
        {"title": "Capture network forensics", "type": "investigate", "desc": "Collect PCAP or NetFlow records for the suspect transfer."},
        {"title": "Identify exfiltrated data", "type": "investigate", "desc": "Determine what data may have been transferred based on volume and destination."},
        {"title": "Notify data protection team", "type": "escalate", "desc": "Alert the DLP team for potential data breach assessment."},
    ],
    "T1071.004": [
        {"title": "Block suspicious domain", "type": "contain", "desc": "Add the suspected C2 domain to DNS sinkhole."},
        {"title": "Isolate affected host", "type": "contain", "desc": "Network-quarantine the host communicating via DNS tunnel."},
        {"title": "Analyze DNS query patterns", "type": "investigate", "desc": "Review full DNS logs for the host to identify C2 communication patterns."},
    ],
    "T1078.003": [
        {"title": "Revoke elevated permissions", "type": "contain", "desc": "Remove the assumed role or elevated privileges immediately."},
        {"title": "Review cloud audit trail", "type": "investigate", "desc": "Examine all actions performed with elevated privileges."},
        {"title": "Validate authorization", "type": "investigate", "desc": "Confirm with the user's manager whether the role assumption was authorized."},
    ],
    "T1021": [
        {"title": "Review remote session logs", "type": "investigate", "desc": "Examine RDP/SSH session records for lateral movement indicators."},
        {"title": "Check for persistence", "type": "investigate", "desc": "Look for scheduled tasks, services, or registry modifications on target hosts."},
        {"title": "Segment network", "type": "contain", "desc": "Implement micro-segmentation to limit lateral movement paths."},
    ],
    "T1059": [
        {"title": "Quarantine affected endpoint", "type": "contain", "desc": "Isolate the host running suspicious commands from the network."},
        {"title": "Collect memory dump", "type": "investigate", "desc": "Capture volatile memory for forensic analysis before remediation."},
        {"title": "Scan for malware artifacts", "type": "investigate", "desc": "Run EDR full scan and check for known IOCs on the endpoint."},
        {"title": "Block script execution", "type": "contain", "desc": "Apply AppLocker/WDAC policies to restrict encoded script execution."},
    ],
}

# Default actions when no specific playbook matches
_DEFAULT_ACTIONS: list[dict[str, str]] = [
    {"title": "Gather additional context", "type": "investigate", "desc": "Collect logs, artifacts, and user statements related to the incident."},
    {"title": "Assess blast radius", "type": "investigate", "desc": "Determine the scope of potential compromise across related systems."},
    {"title": "Escalate to Tier 2 if needed", "type": "escalate", "desc": "If evidence indicates active compromise, escalate to senior analyst."},
]


def recommend_actions(state: dict[str, Any]) -> dict[str, Any]:
    """
    Generate prioritised investigative next actions based on
    incident classification, MITRE techniques, and entity context (FR-07).
    """
    raw_alerts: list[dict] = state.get("raw_alerts", [])
    entity_context: list[dict] = state.get("entity_context", [])
    classifications: list[dict] = state.get("classifications", [])

    # Collect all MITRE techniques
    all_techniques: set[str] = set()
    for alert in raw_alerts:
        all_techniques.update(alert.get("mitre_technique_ids", []))

    # Collect playbook actions for matched techniques
    seen_titles: set[str] = set()
    actions: list[dict] = []
    order = 0

    for technique in sorted(all_techniques):
        playbook = _PLAYBOOK_ACTIONS.get(technique, [])
        for action_template in playbook:
            title = action_template["title"]
            if title in seen_titles:
                continue
            seen_titles.add(title)
            order += 1

            # Determine target entity
            target = None
            for entity in entity_context:
                if action_template["type"] == "contain":
                    if entity.get("entity_type") in ("host", "ip"):
                        target = entity.get("entity_id")
                        break
                elif entity.get("entity_type") == "user":
                    target = entity.get("entity_id")
                    break

            actions.append({
                "action_id": f"act-{uuid.uuid4().hex[:12]}",
                "title": title,
                "description": action_template["desc"],
                "priority_order": order,
                "action_type": action_template["type"],
                "target_entity": target,
            })

    # Add defaults if no specific actions matched
    if not actions:
        for action_template in _DEFAULT_ACTIONS:
            order += 1
            actions.append({
                "action_id": f"act-{uuid.uuid4().hex[:12]}",
                "title": action_template["title"],
                "description": action_template["desc"],
                "priority_order": order,
                "action_type": action_template["type"],
                "target_entity": None,
            })

    # Prioritise: contain > investigate > escalate > notify
    type_order = {"contain": 0, "investigate": 1, "escalate": 2, "notify": 3}
    actions.sort(key=lambda a: (type_order.get(a["action_type"], 9), a["priority_order"]))
    # Reassign priority order after sort
    for i, action in enumerate(actions):
        action["priority_order"] = i + 1

    logger.info("recommend_actions", action_count=len(actions))
    return {"recommended_actions": actions}
