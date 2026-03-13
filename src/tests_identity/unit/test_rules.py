"""Unit tests for the IdentityRuleEngine."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.rules.engine import IdentityRuleEngine, BASELINE_RULES


class TestIdentityRuleEngine:
    """Verify rule engine configuration and evaluation."""

    def test_default_rule_count(self):
        engine = IdentityRuleEngine()
        assert engine.rule_count == 7

    def test_add_custom_rule(self):
        engine = IdentityRuleEngine()
        engine.add_rule(lambda ctx: {"rule_id": "CUSTOM-001", "severity": "low"})
        assert engine.rule_count == 8

    def test_disable_rule(self):
        engine = IdentityRuleEngine()
        engine.disable_rule("IAM-SESSION-001")
        result = engine.evaluate({"is_impossible_travel": True, "travel_speed_kmh": 1200})
        rule_ids = {r["rule_id"] for r in result}
        assert "IAM-SESSION-001" not in rule_ids

    def test_enable_rule(self):
        engine = IdentityRuleEngine()
        engine.disable_rule("IAM-SESSION-001")
        engine.enable_rule("IAM-SESSION-001")
        result = engine.evaluate({"is_impossible_travel": True, "travel_speed_kmh": 1200})
        rule_ids = {r["rule_id"] for r in result}
        assert "IAM-SESSION-001" in rule_ids


class TestImpossibleTravelRule:
    def test_triggers_on_impossible_travel(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"is_impossible_travel": True, "travel_speed_kmh": 1200})
        ids = {r["rule_id"] for r in result}
        assert "IAM-SESSION-001" in ids

    def test_no_trigger_without_travel(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"is_impossible_travel": False})
        ids = {r["rule_id"] for r in result}
        assert "IAM-SESSION-001" not in ids


class TestOffHoursRule:
    def test_triggers_on_off_hours(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"is_off_hours": True})
        ids = {r["rule_id"] for r in result}
        assert "IAM-SESSION-002" in ids

    def test_no_trigger_business_hours(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"is_off_hours": False})
        ids = {r["rule_id"] for r in result}
        assert "IAM-SESSION-002" not in ids


class TestNewDeviceRule:
    def test_triggers_on_new_device(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"is_new_device": True, "device_id": "DEV-999"})
        ids = {r["rule_id"] for r in result}
        assert "IAM-SESSION-003" in ids


class TestBruteForceRule:
    def test_triggers_at_threshold(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"failed_login_count_24h": 5})
        ids = {r["rule_id"] for r in result}
        assert "IAM-TAKEOVER-001" in ids

    def test_no_trigger_below_threshold(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"failed_login_count_24h": 4})
        ids = {r["rule_id"] for r in result}
        assert "IAM-TAKEOVER-001" not in ids

    def test_critical_severity_at_10(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"failed_login_count_24h": 10})
        bf = [r for r in result if r["rule_id"] == "IAM-TAKEOVER-001"]
        assert bf[0]["severity"] == "critical"


class TestMfaFatigueRule:
    def test_triggers_at_threshold(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"mfa_denied_count_1h": 5})
        ids = {r["rule_id"] for r in result}
        assert "IAM-TAKEOVER-002" in ids

    def test_no_trigger_below(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"mfa_denied_count_1h": 4})
        ids = {r["rule_id"] for r in result}
        assert "IAM-TAKEOVER-002" not in ids


class TestPrivilegeEscalationRule:
    def test_triggers_on_self_escalation(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"is_self_escalation": True, "role_name": "global_admin"})
        ids = {r["rule_id"] for r in result}
        assert "IAM-PRIV-001" in ids


class TestSodViolationRule:
    def test_triggers_on_conflicts(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"conflicting_roles": ["admin", "auditor"]})
        ids = {r["rule_id"] for r in result}
        assert "IAM-PRIV-002" in ids

    def test_no_trigger_empty_conflicts(self):
        engine = IdentityRuleEngine()
        result = engine.evaluate({"conflicting_roles": []})
        ids = {r["rule_id"] for r in result}
        assert "IAM-PRIV-002" not in ids
