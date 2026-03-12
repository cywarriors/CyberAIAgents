"""Scenario-based detection tests for the VAPT agent.

Each scenario injects specific vulnerability patterns and asserts the
pipeline produces the expected findings and severity classifications.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from vapt_agent.nodes.validate_roe import validate_roe
from vapt_agent.nodes.validate_exploits import validate_exploits
from vapt_agent.nodes.analyze_attack_paths import analyze_attack_paths
from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
from vapt_agent.nodes.generate_remediation import generate_remediation
from vapt_agent.nodes.generate_report import generate_report
from vapt_agent.nodes.publish_findings import publish_findings
from vapt_agent.rules.engine import VulnRulesEngine
from vapt_agent.rules.vuln_rules import BASELINE_RULES
from tests_vapt.mocks.scenarios import SCENARIOS, VAPTScenario


def _merge(base: dict, update: dict) -> dict:
    merged = dict(base)
    for key, val in update.items():
        if isinstance(val, list) and isinstance(merged.get(key), list):
            merged[key] = merged[key] + val
        else:
            merged[key] = val
    return merged


def _run_scenario(scenario: VAPTScenario) -> dict[str, Any]:
    """Run a single scenario through the VAPT pipeline (nodes 1, 4–9)."""
    state: dict[str, Any] = {
        "roe_authorization": scenario.roe,
        "roe_validated": False,
        "discovered_assets": scenario.injected_assets,
        "scan_results": scenario.injected_findings,
        "validated_exploits": [],
        "attack_paths": [],
        "risk_scores": [],
        "remediation_items": [],
        "report_artifacts": [],
        "published_findings": [],
        "errors": [],
    }

    state = _merge(state, validate_roe(state))
    if not state.get("roe_validated"):
        return state

    state = _merge(state, validate_exploits(state))
    state = _merge(state, analyze_attack_paths(state))
    state = _merge(state, score_and_prioritize(state))
    state = _merge(state, generate_remediation(state))
    state = _merge(state, generate_report(state))

    with patch("vapt_agent.nodes.publish_findings.create_ticket", return_value="TKT-SCEN"), \
         patch("vapt_agent.nodes.publish_findings.send_notification", return_value=True):
        state = _merge(state, publish_findings(state))

    return state


@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=[s.name for s in SCENARIOS],
)
class TestScenarioDetection:
    """Parametrised tests – one run per scenario."""

    def test_minimum_findings(self, scenario: VAPTScenario):
        result = _run_scenario(scenario)
        assert result["roe_validated"] is True
        assert len(result["risk_scores"]) >= scenario.expected_min_findings

    def test_severity_classification(self, scenario: VAPTScenario):
        result = _run_scenario(scenario)
        scores = result["risk_scores"]

        critical_count = sum(1 for s in scores if s.get("severity") == "critical")
        high_count = sum(1 for s in scores if s.get("severity") == "high")

        assert critical_count >= scenario.expected_min_critical, (
            f"Expected >= {scenario.expected_min_critical} critical, got {critical_count}"
        )
        assert high_count >= scenario.expected_min_high, (
            f"Expected >= {scenario.expected_min_high} high, got {high_count}"
        )

    def test_expected_rules_fire(self, scenario: VAPTScenario):
        """Each injected finding should trigger the expected baseline rules."""
        engine = VulnRulesEngine()
        for rule_id, fn in BASELINE_RULES.items():
            engine.add(rule_id, fn)

        fired_rules: set[str] = set()
        for finding in scenario.injected_findings:
            matches = engine.evaluate(finding)
            fired_rules.update(m["rule_id"] for m in matches)

        for expected_id in scenario.expected_rule_ids:
            assert expected_id in fired_rules, (
                f"Rule {expected_id} did not fire for scenario '{scenario.name}'"
            )

    def test_report_generated(self, scenario: VAPTScenario):
        result = _run_scenario(scenario)
        assert len(result["report_artifacts"]) == 3

    def test_findings_published(self, scenario: VAPTScenario):
        result = _run_scenario(scenario)
        assert len(result["published_findings"]) == len(result["risk_scores"])


class TestDetectionCoverage:
    """Aggregate coverage check across all scenarios."""

    def test_ninety_percent_rule_coverage(self):
        """At least 90% of baseline rules should fire across all scenarios."""
        engine = VulnRulesEngine()
        for rule_id, fn in BASELINE_RULES.items():
            engine.add(rule_id, fn)

        all_fired: set[str] = set()
        for scenario in SCENARIOS:
            for finding in scenario.injected_findings:
                matches = engine.evaluate(finding)
                all_fired.update(m["rule_id"] for m in matches)

        total_rules = len(BASELINE_RULES)
        coverage = len(all_fired) / total_rules
        assert coverage >= 0.90, (
            f"Rule coverage {coverage:.0%} < 90%. "
            f"Fired: {all_fired}, Total: {set(BASELINE_RULES.keys())}"
        )
