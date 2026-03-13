"""Named attack scenarios for identity access monitoring integration tests.

Each scenario bundles auth events + role changes with expected detection outcomes
to validate the full LangGraph pipeline end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tests_identity.mocks.generators import (
    generate_brute_force_events,
    generate_high_risk_role_changes,
    generate_impossible_travel_events,
    generate_mfa_bypass_events,
    generate_mfa_fatigue_events,
    generate_new_device_events,
    generate_normal_auth_events,
    generate_normal_role_changes,
    generate_off_hours_events,
    generate_self_escalation_role_changes,
    generate_sod_violating_role_changes,
    generate_lockout_events,
    generate_impossible_travel_with_vpn,
)


@dataclass
class IdentityScenario:
    """Describes an identity attack scenario with expected outcomes."""

    name: str
    description: str
    auth_events: list[dict[str, Any]] = field(default_factory=list)
    role_changes: list[dict[str, Any]] = field(default_factory=list)
    expected_anomaly_types: list[str] = field(default_factory=list)
    expected_takeover_signals: list[str] = field(default_factory=list)
    expected_privilege_alerts: list[str] = field(default_factory=list)
    expected_sod_violations: int = 0
    min_expected_risk_level: str = "low"
    should_generate_alert: bool = False


SCENARIOS: list[IdentityScenario] = [
    IdentityScenario(
        name="clean_baseline",
        description="Normal user activity – no attacks, all benign",
        auth_events=generate_normal_auth_events(10),
        role_changes=generate_normal_role_changes(3),
        expected_anomaly_types=[],
        expected_takeover_signals=[],
        expected_privilege_alerts=[],
        expected_sod_violations=0,
        min_expected_risk_level="low",
        should_generate_alert=False,
    ),
    IdentityScenario(
        name="brute_force_attack",
        description="8 failed logins from Moscow followed by 1 success",
        auth_events=generate_brute_force_events(failure_count=8),
        expected_takeover_signals=["brute_force"],
        min_expected_risk_level="high",
        should_generate_alert=True,
    ),
    IdentityScenario(
        name="impossible_travel",
        description="Login from NYC then Tokyo 30 minutes later",
        auth_events=generate_impossible_travel_events(),
        expected_anomaly_types=["impossible_travel"],
        min_expected_risk_level="medium",
        should_generate_alert=True,
    ),
    IdentityScenario(
        name="mfa_fatigue",
        description="7 MFA denials in rapid succession (push bombing)",
        auth_events=generate_mfa_fatigue_events(denial_count=7),
        expected_takeover_signals=["mfa_fatigue"],
        min_expected_risk_level="high",
        should_generate_alert=True,
    ),
    IdentityScenario(
        name="off_hours_login",
        description="Login at 03:00 UTC outside business hours",
        auth_events=generate_off_hours_events(),
        expected_anomaly_types=["off_hours_login"],
        min_expected_risk_level="low",
        should_generate_alert=False,
    ),
    IdentityScenario(
        name="new_device_login",
        description="User logs in from 3 different devices",
        auth_events=generate_new_device_events(),
        expected_anomaly_types=["new_device"],
        min_expected_risk_level="low",
        should_generate_alert=False,
    ),
    IdentityScenario(
        name="privilege_escalation",
        description="User assigns global_admin + security_admin to themselves",
        role_changes=generate_self_escalation_role_changes(),
        expected_privilege_alerts=["self_privilege_escalation"],
        min_expected_risk_level="medium",
        should_generate_alert=True,
    ),
    IdentityScenario(
        name="sod_violation",
        description="User holds both finance_approver and finance_requester",
        role_changes=generate_sod_violating_role_changes(),
        expected_sod_violations=1,
        min_expected_risk_level="medium",
        should_generate_alert=False,
    ),
    IdentityScenario(
        name="mfa_bypass",
        description="Failures then success without MFA – bypass suspected",
        auth_events=generate_mfa_bypass_events(),
        expected_takeover_signals=["mfa_bypass_suspected"],
        min_expected_risk_level="high",
        should_generate_alert=True,
    ),
    IdentityScenario(
        name="account_lockout",
        description="Failed logins leading to account lockout",
        auth_events=generate_lockout_events(),
        expected_takeover_signals=["account_lockout"],
        min_expected_risk_level="low",
        should_generate_alert=False,
    ),
    IdentityScenario(
        name="vpn_impossible_travel_benign",
        description="Impossible travel but one IP is VPN – should NOT flag",
        auth_events=generate_impossible_travel_with_vpn(),
        expected_anomaly_types=[],
        expected_takeover_signals=[],
        min_expected_risk_level="low",
        should_generate_alert=False,
    ),
]
