"""PrivilegeChangeNode – detect escalation and toxic entitlement / SoD violations (FR-04/07)."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Predefined SoD conflict pairs (FR-07)
_SOD_CONFLICTS: list[tuple[str, str, str]] = [
    ("finance_approver", "finance_requester", "SOD-FIN-001"),
    ("admin", "auditor", "SOD-ADM-001"),
    ("developer", "production_deployer", "SOD-DEV-001"),
    ("hr_admin", "payroll_admin", "SOD-HR-001"),
    ("security_admin", "system_admin", "SOD-SEC-001"),
]

_HIGH_RISK_ROLES = frozenset({
    "global_admin", "security_admin", "domain_admin", "exchange_admin",
    "privileged_role_admin", "billing_admin", "root", "superadmin",
})


def detect_privilege_changes(state: dict[str, Any]) -> dict[str, Any]:
    """Detect privilege escalation and SoD violations.

    Implements FR-04 (privilege escalation monitoring) and
    FR-07 (toxic entitlement / SoD detection).
    """
    role_changes: list[dict] = state.get("raw_role_changes", [])

    logger.info("detect_privilege_changes", event_count=len(role_changes))

    privilege_alerts: list[dict[str, Any]] = []
    sod_violations: list[dict[str, Any]] = []

    # Track accumulated roles per user in this batch
    user_roles: dict[str, set[str]] = {}

    for evt in role_changes:
        user_id = evt.get("user_id", "")
        username = evt.get("username", "")
        action = evt.get("action", "")
        role_name = evt.get("role_name", "").lower()
        risk_level = evt.get("role_risk_level", "low")
        changed_by = evt.get("changed_by", "")

        if user_id not in user_roles:
            user_roles[user_id] = set()

        if action in ("role_assigned", "permission_granted", "group_added"):
            user_roles[user_id].add(role_name)

            # High-risk role assignment alert
            if role_name in _HIGH_RISK_ROLES or risk_level in ("high", "critical"):
                privilege_alerts.append({
                    "user_id": user_id,
                    "username": username,
                    "alert_type": "high_risk_role_assignment",
                    "severity": "high",
                    "role_name": role_name,
                    "risk_level": risk_level,
                    "changed_by": changed_by,
                    "justification": evt.get("justification", ""),
                    "evidence": f"High-risk role '{role_name}' assigned to {username} by {changed_by}",
                    "source_event_id": evt.get("event_id", ""),
                })

            # Self-assignment detection
            if changed_by and changed_by == user_id:
                privilege_alerts.append({
                    "user_id": user_id,
                    "username": username,
                    "alert_type": "self_privilege_escalation",
                    "severity": "critical",
                    "role_name": role_name,
                    "risk_level": risk_level,
                    "changed_by": changed_by,
                    "evidence": f"User {username} assigned role '{role_name}' to themselves",
                    "source_event_id": evt.get("event_id", ""),
                })

    # SoD violation check across accumulated roles
    for user_id, roles in user_roles.items():
        for role_a, role_b, rule_id in _SOD_CONFLICTS:
            if role_a in roles and role_b in roles:
                sod_violations.append({
                    "user_id": user_id,
                    "username": "",  # filled later if available
                    "conflicting_roles": [role_a, role_b],
                    "rule_id": rule_id,
                    "rule_name": f"SoD conflict: {role_a} + {role_b}",
                    "severity": "high",
                    "recommendation": f"Remove one of: {role_a}, {role_b}",
                })

    logger.info(
        "privilege_analysis_complete",
        alerts=len(privilege_alerts),
        sod_violations=len(sod_violations),
    )
    return {"privilege_alerts": privilege_alerts, "sod_violations": sod_violations}
