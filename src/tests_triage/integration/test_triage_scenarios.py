"""Triage scenario tests – validate priority agreement (SRS-02 §14 AC-01: ≥85%)."""

import pytest
from tests_triage.mocks.scenarios import SCENARIOS, TriageScenario
from incident_triage_agent.nodes.ingest import ingest_alert
from incident_triage_agent.nodes.correlate import correlate_incident
from incident_triage_agent.nodes.enrich import enrich_entity
from incident_triage_agent.nodes.risk_score import risk_score
from incident_triage_agent.nodes.summarize import generate_summary
from incident_triage_agent.nodes.recommend import recommend_actions
from incident_triage_agent.nodes.case_manager import create_or_update_case


def _triage(scenario: TriageScenario) -> dict:
    """Run full triage pipeline for a scenario."""
    state: dict = {"raw_alerts": scenario.alerts}
    state.update(ingest_alert(state))
    state.update(correlate_incident(state))
    state.update(enrich_entity(state))
    state.update(risk_score(state))
    state.update(generate_summary(state))
    state.update(recommend_actions(state))
    state.update(create_or_update_case(state))
    return state


_PRIORITY_RANK = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}


@pytest.mark.triage
class TestTriageScenarios:
    @pytest.mark.parametrize(
        "scenario",
        SCENARIOS,
        ids=[s.name for s in SCENARIOS],
    )
    def test_scenario_produces_incident(self, scenario: TriageScenario):
        """Each scenario should produce at least one triaged incident."""
        state = _triage(scenario)
        assert len(state["triaged_incidents"]) > 0, (
            f"Scenario '{scenario.name}' produced no triaged incidents"
        )

    @pytest.mark.parametrize(
        "scenario",
        SCENARIOS,
        ids=[s.name for s in SCENARIOS],
    )
    def test_priority_within_one_level(self, scenario: TriageScenario):
        """Computed priority should be within ±1 level of expected."""
        state = _triage(scenario)
        inc = state["triaged_incidents"][0]
        actual_rank = _PRIORITY_RANK.get(inc["priority"], 0)
        expected_rank = _PRIORITY_RANK.get(scenario.expected_priority, 0)
        diff = abs(actual_rank - expected_rank)
        assert diff <= 1, (
            f"Scenario '{scenario.name}': expected {scenario.expected_priority}, "
            f"got {inc['priority']} (diff={diff})"
        )

    @pytest.mark.parametrize(
        "scenario",
        SCENARIOS,
        ids=[s.name for s in SCENARIOS],
    )
    def test_recommendations_present(self, scenario: TriageScenario):
        """Scenarios expecting recommendations should have them."""
        if not scenario.expected_has_recommendations:
            pytest.skip("Scenario does not expect recommendations")
        state = _triage(scenario)
        inc = state["triaged_incidents"][0]
        assert len(inc.get("recommended_actions", [])) > 0

    @pytest.mark.parametrize(
        "scenario",
        SCENARIOS,
        ids=[s.name for s in SCENARIOS],
    )
    def test_correlation_groups_minimum(self, scenario: TriageScenario):
        """Should produce at least the expected number of correlation groups."""
        state = _triage(scenario)
        assert len(state["correlations"]) >= scenario.expected_min_correlation_groups

    def test_overall_priority_agreement_above_85_percent(self):
        """AC-01: ≥85% of scenarios must have priority within ±1 level of expected."""
        agreed = 0
        for scenario in SCENARIOS:
            state = _triage(scenario)
            inc = state["triaged_incidents"][0]
            actual_rank = _PRIORITY_RANK.get(inc["priority"], 0)
            expected_rank = _PRIORITY_RANK.get(scenario.expected_priority, 0)
            if abs(actual_rank - expected_rank) <= 1:
                agreed += 1
        agreement = agreed / len(SCENARIOS) if SCENARIOS else 0
        assert agreement >= 0.85, f"Priority agreement {agreement:.0%} < 85%"
