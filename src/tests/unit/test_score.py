"""Unit tests for ScoreAndPrioritizeNode."""

import pytest
from threat_detection_agent.nodes.score import score_and_prioritize


class TestScoreAndPrioritize:
    def test_rule_match_becomes_candidate(self):
        state = {
            "matched_rules": [
                {
                    "rule_id": "RULE-AUTH-001",
                    "rule_name": "Brute Force",
                    "mitre_technique_id": "T1110",
                    "mitre_tactic": "Credential Access",
                    "severity": "High",
                    "matched_event_ids": ["evt-001"],
                    "description": "test",
                    "raw_evidence": [],
                }
            ],
            "anomalies": [],
        }
        result = score_and_prioritize(state)
        assert len(result["alert_candidates"]) == 1
        c = result["alert_candidates"][0]
        assert c["severity"] == "High"
        assert c["confidence"] == 85
        assert "T1110" in c["mitre_technique_ids"]
        assert c["source_type"] == "rule"

    def test_anomaly_becomes_candidate(self):
        state = {
            "matched_rules": [],
            "anomalies": [
                {
                    "model_id": "baseline-auth-v1",
                    "anomaly_type": "excessive_failed_logins",
                    "anomaly_score": 0.85,
                    "baseline_value": 2.0,
                    "observed_value": 20.0,
                    "entity_type": "user",
                    "entity_id": "eve",
                    "matched_event_ids": ["evt-002"],
                    "description": "test anomaly",
                }
            ],
        }
        result = score_and_prioritize(state)
        assert len(result["alert_candidates"]) == 1
        c = result["alert_candidates"][0]
        assert c["source_type"] == "anomaly"
        assert c["confidence"] == 85

    def test_overlapping_events_merged_to_hybrid(self):
        shared_event = "evt-shared"
        state = {
            "matched_rules": [
                {
                    "rule_id": "R1",
                    "rule_name": "R1",
                    "mitre_technique_id": "T1110",
                    "mitre_tactic": "Credential Access",
                    "severity": "High",
                    "matched_event_ids": [shared_event],
                    "description": "rule desc",
                    "raw_evidence": [],
                }
            ],
            "anomalies": [
                {
                    "model_id": "m1",
                    "anomaly_type": "t",
                    "anomaly_score": 0.7,
                    "baseline_value": 1,
                    "observed_value": 10,
                    "entity_type": "user",
                    "entity_id": "alice",
                    "matched_event_ids": [shared_event],
                    "description": "anomaly desc",
                }
            ],
        }
        result = score_and_prioritize(state)
        assert len(result["alert_candidates"]) == 1
        c = result["alert_candidates"][0]
        assert c["source_type"] == "hybrid"
        # Corroboration should boost confidence
        assert c["confidence"] > 70

    def test_empty_inputs(self):
        result = score_and_prioritize({"matched_rules": [], "anomalies": []})
        assert result["alert_candidates"] == []
