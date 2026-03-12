"""Unit tests for RiskScoreNode."""

from incident_triage_agent.nodes.risk_score import risk_score
from tests_triage.mocks.generators import (
    generate_brute_force_alert,
    generate_data_exfil_alert,
    generate_ransomware_alert,
    generate_benign_auth_alert,
    generate_multi_stage_intrusion,
)


def _make_state(alerts, entity_context=None, correlations=None):
    """Helper to build minimal state dict for risk_score node."""
    return {
        "raw_alerts": alerts,
        "entity_context": entity_context or [],
        "correlations": correlations or [],
    }


class TestRiskScore:
    def test_produces_priority_for_single_alert(self):
        alert = generate_brute_force_alert()
        result = risk_score(_make_state([alert]))
        scores = result["priority_scores"]
        assert len(scores) >= 1
        assert scores[0]["priority"] in ("P1", "P2", "P3", "P4")

    def test_critical_alert_gets_high_priority(self):
        alert = generate_ransomware_alert()
        entity_context = [
            {"entity_type": "host", "asset_criticality": "critical", "entity_id": "srv-db-01"},
            {"entity_type": "user", "is_privileged": False, "entity_id": "bob", "user_role": "analyst"},
        ]
        result = risk_score(_make_state([alert], entity_context))
        scores = result["priority_scores"]
        assert scores[0]["priority"] in ("P1", "P2")

    def test_benign_alert_gets_low_priority(self):
        alert = generate_benign_auth_alert()
        result = risk_score(_make_state([alert]))
        scores = result["priority_scores"]
        assert scores[0]["priority"] in ("P3", "P4")

    def test_score_components_present(self):
        alert = generate_data_exfil_alert()
        result = risk_score(_make_state([alert]))
        components = result["priority_scores"][0]["components"]
        assert "asset_criticality" in components
        assert "threat_intel" in components
        assert "user_risk" in components
        assert "alert_severity" in components
        assert "historical_accuracy" in components

    def test_multi_stage_scores_higher(self):
        """Multi-alert correlated group should score higher than a single benign alert."""
        chain_alerts = generate_multi_stage_intrusion()
        correlations = [{
            "group_id": "corr-chain",
            "alert_ids": [a["alert_id"] for a in chain_alerts],
            "shared_entities": ["bob", "ws-002"],
            "attack_chain": ["Initial Access", "Credential Access", "Lateral Movement", "Exfiltration"],
        }]
        entity_context = [
            {"entity_type": "user", "entity_id": "bob", "is_privileged": False, "user_role": "analyst"},
            {"entity_type": "host", "entity_id": "srv-db-01", "asset_criticality": "critical"},
        ]
        chain_result = risk_score(_make_state(chain_alerts, entity_context, correlations))

        single_alert = generate_benign_auth_alert()
        single_result = risk_score(_make_state([single_alert]))

        assert chain_result["priority_scores"][0]["raw_score"] > single_result["priority_scores"][0]["raw_score"]

    def test_score_within_bounds(self):
        alert = generate_data_exfil_alert()
        result = risk_score(_make_state([alert]))
        score = result["priority_scores"][0]["raw_score"]
        assert 0 <= score <= 100

    def test_explanation_present(self):
        alert = generate_brute_force_alert()
        result = risk_score(_make_state([alert]))
        assert "explanation" in result["priority_scores"][0]
        assert result["priority_scores"][0]["explanation"]

    def test_confidence_matches_score(self):
        alert = generate_data_exfil_alert()
        result = risk_score(_make_state([alert]))
        ps = result["priority_scores"][0]
        assert ps["confidence"] == min(int(ps["raw_score"]), 100)
