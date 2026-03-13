"""Unit tests for the detect_privilege_changes node (FR-04/07)."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.nodes.privilege import detect_privilege_changes


class TestDetectPrivilegeChanges:
    """Verify privilege escalation and SoD violation detection."""

    def test_empty_input(self, empty_state: dict[str, Any]):
        result = detect_privilege_changes(empty_state)
        assert result["privilege_alerts"] == []
        assert result["sod_violations"] == []

    def test_normal_roles_no_alerts(self, normal_role_changes: list[dict]):
        state = {"raw_role_changes": normal_role_changes}
        result = detect_privilege_changes(state)
        assert result["privilege_alerts"] == []
        assert result["sod_violations"] == []

    def test_high_risk_role_detected(self, high_risk_role_changes: list[dict]):
        state = {"raw_role_changes": high_risk_role_changes}
        result = detect_privilege_changes(state)
        alert_types = {a["alert_type"] for a in result["privilege_alerts"]}
        assert "high_risk_role_assignment" in alert_types

    def test_high_risk_role_fields(self, high_risk_role_changes: list[dict]):
        state = {"raw_role_changes": high_risk_role_changes}
        result = detect_privilege_changes(state)
        alerts = [a for a in result["privilege_alerts"] if a["alert_type"] == "high_risk_role_assignment"]
        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert["severity"] == "high"
        assert "global_admin" in alert["role_name"] or "security_admin" in alert["role_name"]
        assert alert["evidence"]

    def test_self_escalation_detected(self, self_escalation_role_changes: list[dict]):
        state = {"raw_role_changes": self_escalation_role_changes}
        result = detect_privilege_changes(state)
        alert_types = {a["alert_type"] for a in result["privilege_alerts"]}
        assert "self_privilege_escalation" in alert_types

    def test_self_escalation_is_critical(self, self_escalation_role_changes: list[dict]):
        state = {"raw_role_changes": self_escalation_role_changes}
        result = detect_privilege_changes(state)
        self_esc = [a for a in result["privilege_alerts"] if a["alert_type"] == "self_privilege_escalation"]
        assert all(a["severity"] == "critical" for a in self_esc)

    def test_sod_violation_detected(self, sod_violating_role_changes: list[dict]):
        state = {"raw_role_changes": sod_violating_role_changes}
        result = detect_privilege_changes(state)
        assert len(result["sod_violations"]) >= 1

    def test_sod_violation_fields(self, sod_violating_role_changes: list[dict]):
        state = {"raw_role_changes": sod_violating_role_changes}
        result = detect_privilege_changes(state)
        sod = result["sod_violations"][0]
        assert "conflicting_roles" in sod
        assert len(sod["conflicting_roles"]) == 2
        assert sod["rule_id"].startswith("SOD-")
        assert sod["severity"] == "high"
        assert sod["recommendation"]

    def test_sod_finance_conflict(self):
        from tests_identity.mocks.generators import generate_sod_violating_role_changes
        changes = generate_sod_violating_role_changes(pair_index=0)
        state = {"raw_role_changes": changes}
        result = detect_privilege_changes(state)
        sod = result["sod_violations"][0]
        assert "finance_approver" in sod["conflicting_roles"]
        assert "finance_requester" in sod["conflicting_roles"]
        assert sod["rule_id"] == "SOD-FIN-001"

    def test_sod_admin_auditor_conflict(self):
        from tests_identity.mocks.generators import generate_sod_violating_role_changes
        changes = generate_sod_violating_role_changes(pair_index=1)
        state = {"raw_role_changes": changes}
        result = detect_privilege_changes(state)
        sod = result["sod_violations"][0]
        assert "admin" in sod["conflicting_roles"]
        assert "auditor" in sod["conflicting_roles"]
        assert sod["rule_id"] == "SOD-ADM-001"

    def test_role_removal_does_not_trigger(self):
        """role_removed action should not trigger alerts."""
        state = {"raw_role_changes": [{
            "user_id": "U1", "username": "test", "action": "role_removed",
            "role_name": "global_admin", "role_risk_level": "critical",
            "changed_by": "admin-001",
        }]}
        result = detect_privilege_changes(state)
        assert result["privilege_alerts"] == []

    def test_mixed_role_batch(self, mixed_role_batch: list[dict]):
        state = {"raw_role_changes": mixed_role_batch}
        result = detect_privilege_changes(state)
        # Should contain both privilege alerts and SoD violations
        assert len(result["privilege_alerts"]) >= 1
        assert len(result["sod_violations"]) >= 1
