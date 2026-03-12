"""Unit tests for CreateOrUpdateCaseNode."""

from incident_triage_agent.nodes.case_manager import create_or_update_case
from tests_triage.mocks.generators import (
    generate_brute_force_alert,
    generate_ransomware_alert,
)


def _make_state(alerts, **overrides):
    state = {
        "raw_alerts": alerts,
        "entity_context": overrides.get("entity_context", []),
        "correlations": overrides.get("correlations", []),
        "priority_scores": overrides.get("priority_scores", []),
        "triage_summaries": overrides.get("triage_summaries", []),
        "classifications": overrides.get("classifications", []),
        "recommended_actions": overrides.get("recommended_actions", []),
    }
    return state


class TestCreateOrUpdateCase:
    def test_creates_incident(self):
        alert = generate_brute_force_alert()
        state = _make_state(
            [alert],
            priority_scores=[{"priority": "P2", "confidence": 70, "components": {}}],
            triage_summaries=[{"text": "Test summary", "classification": "credential_abuse"}],
            classifications=[{"classification": "credential_abuse", "confidence": 70}],
        )
        result = create_or_update_case(state)
        assert len(result["triaged_incidents"]) == 1
        inc = result["triaged_incidents"][0]
        assert inc["incident_id"].startswith("inc-")
        assert inc["case_id"].startswith("case-")

    def test_case_id_returned(self):
        alert = generate_brute_force_alert()
        state = _make_state(
            [alert],
            priority_scores=[{"priority": "P3", "confidence": 50}],
            classifications=[{"classification": "credential_abuse"}],
        )
        result = create_or_update_case(state)
        assert len(result["case_ids"]) == 1
        assert result["case_ids"][0]["case_id"].startswith("case-")

    def test_timeline_includes_alerts_and_triage(self):
        alert = generate_brute_force_alert()
        state = _make_state(
            [alert],
            priority_scores=[{"priority": "P2", "confidence": 60}],
            classifications=[{"classification": "credential_abuse"}],
        )
        result = create_or_update_case(state)
        timeline = result["incident_timeline"]
        # Should have at least one alert event + triage_completed event
        assert len(timeline) >= 2
        event_types = [e["event_type"] for e in timeline]
        assert "alert_ingested" in event_types
        assert "triage_completed" in event_types

    def test_severity_mapping(self):
        alert = generate_ransomware_alert()
        state = _make_state(
            [alert],
            priority_scores=[{"priority": "P1", "confidence": 95}],
            classifications=[{"classification": "ransomware"}],
        )
        result = create_or_update_case(state)
        inc = result["triaged_incidents"][0]
        assert inc["severity"] == "Critical"

    def test_incident_contains_mitre_data(self):
        alert = generate_brute_force_alert()
        state = _make_state(
            [alert],
            priority_scores=[{"priority": "P2", "confidence": 70}],
            classifications=[{"classification": "credential_abuse"}],
        )
        result = create_or_update_case(state)
        inc = result["triaged_incidents"][0]
        assert "mitre_technique_ids" in inc
        assert "mitre_tactics" in inc

    def test_empty_alerts_returns_empty(self):
        result = create_or_update_case(_make_state([]))
        assert result["triaged_incidents"] == []
        assert result["case_ids"] == []
        assert result["incident_timeline"] == []

    def test_recommended_actions_included(self):
        alert = generate_brute_force_alert()
        actions = [{"action_id": "act-001", "title": "Lock account", "action_type": "contain"}]
        state = _make_state(
            [alert],
            priority_scores=[{"priority": "P2", "confidence": 70}],
            classifications=[{"classification": "credential_abuse"}],
            recommended_actions=actions,
        )
        result = create_or_update_case(state)
        inc = result["triaged_incidents"][0]
        assert inc["recommended_actions"] == actions
