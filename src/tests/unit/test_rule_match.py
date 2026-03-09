"""Unit tests for RuleMatch node and Rules Engine."""

import pytest
from threat_detection_agent.nodes.normalize import normalize_schema
from threat_detection_agent.nodes.rule_match import rule_match
from tests.mocks.generators import (
    generate_benign_auth_event,
    generate_brute_force_event,
    generate_data_exfil_event,
    generate_dns_tunnelling_event,
    generate_impossible_travel_event,
    generate_lateral_movement_event,
    generate_malware_execution_event,
    generate_privilege_escalation_event,
)


def _normalize_and_match(raw_event):
    """Helper: normalise then run rule match."""
    norm = normalize_schema({"raw_events": [raw_event]})
    return rule_match({"normalized_events": norm["normalized_events"]})


class TestRuleMatch:
    def test_benign_auth_produces_no_match(self):
        result = _normalize_and_match(generate_benign_auth_event())
        assert len(result["matched_rules"]) == 0

    def test_brute_force_detected(self):
        result = _normalize_and_match(generate_brute_force_event())
        assert any(r["rule_id"] == "RULE-AUTH-001" for r in result["matched_rules"])

    def test_impossible_travel_detected(self):
        result = _normalize_and_match(generate_impossible_travel_event())
        assert any(r["rule_id"] == "RULE-AUTH-002" for r in result["matched_rules"])

    def test_data_exfil_detected(self):
        result = _normalize_and_match(generate_data_exfil_event())
        assert any(r["rule_id"] == "RULE-NET-001" for r in result["matched_rules"])

    def test_dns_tunnelling_detected(self):
        result = _normalize_and_match(generate_dns_tunnelling_event())
        assert any(r["rule_id"] == "RULE-DNS-001" for r in result["matched_rules"])

    def test_privilege_escalation_detected(self):
        result = _normalize_and_match(generate_privilege_escalation_event())
        assert any(r["rule_id"] == "RULE-IAM-001" for r in result["matched_rules"])

    def test_lateral_movement_detected(self):
        result = _normalize_and_match(generate_lateral_movement_event())
        assert any(r["rule_id"] == "RULE-NET-002" for r in result["matched_rules"])

    def test_malware_execution_detected(self):
        result = _normalize_and_match(generate_malware_execution_event())
        assert any(r["rule_id"] == "RULE-END-001" for r in result["matched_rules"])

    def test_all_matches_have_mitre_ids(self):
        for gen in [
            generate_brute_force_event,
            generate_data_exfil_event,
            generate_dns_tunnelling_event,
            generate_privilege_escalation_event,
            generate_malware_execution_event,
        ]:
            result = _normalize_and_match(gen())
            for m in result["matched_rules"]:
                assert m.get("mitre_technique_id"), f"Missing MITRE ID in {m['rule_id']}"
