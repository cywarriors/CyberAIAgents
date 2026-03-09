"""Detection tests – seeded attack scenarios validated against expected alerts (§14).

Maps to AC-01: Agent detects >= 90% of seeded attack test scenarios.
"""

import pytest
from tests.mocks.scenarios import SCENARIOS, AttackScenario
from threat_detection_agent.nodes.normalize import normalize_schema
from threat_detection_agent.nodes.rule_match import rule_match


def _detect(scenario: AttackScenario) -> list[dict]:
    """Run normalise + rule_match for a scenario's events."""
    norm_out = normalize_schema({"raw_events": scenario.events})
    return rule_match({"normalized_events": norm_out["normalized_events"]})["matched_rules"]


@pytest.mark.detection
class TestDetectionScenarios:
    @pytest.mark.parametrize(
        "scenario",
        SCENARIOS,
        ids=[s.name for s in SCENARIOS],
    )
    def test_scenario_detected(self, scenario: AttackScenario):
        """Each scenario must trigger at least one of its expected rule IDs."""
        matches = _detect(scenario)
        matched_ids = {m["rule_id"] for m in matches}
        expected = set(scenario.expected_rule_ids)
        assert matched_ids & expected, (
            f"Scenario '{scenario.name}' expected rules {expected} "
            f"but got {matched_ids}"
        )

    @pytest.mark.parametrize(
        "scenario",
        SCENARIOS,
        ids=[s.name for s in SCENARIOS],
    )
    def test_severity_meets_minimum(self, scenario: AttackScenario):
        """Matched rules should meet the scenario's minimum severity."""
        severity_rank = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        min_rank = severity_rank[scenario.expected_min_severity]

        matches = _detect(scenario)
        for m in matches:
            if m["rule_id"] in scenario.expected_rule_ids:
                actual_rank = severity_rank.get(m.get("severity", "Info"), 0)
                assert actual_rank >= min_rank, (
                    f"Rule {m['rule_id']} severity {m.get('severity')} "
                    f"below minimum {scenario.expected_min_severity}"
                )

    def test_overall_coverage_above_90_percent(self):
        """AC-01: >= 90% of scenarios must be detected."""
        detected = 0
        for scenario in SCENARIOS:
            matches = _detect(scenario)
            matched_ids = {m["rule_id"] for m in matches}
            if matched_ids & set(scenario.expected_rule_ids):
                detected += 1
        coverage = detected / len(SCENARIOS) if SCENARIOS else 0
        assert coverage >= 0.9, f"Detection coverage {coverage:.0%} < 90%"
