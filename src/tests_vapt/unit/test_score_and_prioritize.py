"""Unit tests for Node 6 – ScoreAndPrioritize."""

from __future__ import annotations

import pytest
from vapt_agent.nodes.score_and_prioritize import score_and_prioritize


class TestScoreAndPrioritize:
    """Test suite for scoring and prioritization node."""

    def test_scores_all_findings(self, full_state):
        result = score_and_prioritize(full_state)
        scores = result.get("risk_scores", [])
        assert len(scores) == len(full_state["scan_results"])

    def test_scores_sorted_descending(self, full_state):
        result = score_and_prioritize(full_state)
        scores = result.get("risk_scores", [])
        values = [s["composite_score"] for s in scores]
        assert values == sorted(values, reverse=True)

    def test_score_range(self, full_state):
        result = score_and_prioritize(full_state)
        for scored in result.get("risk_scores", []):
            assert 0 <= scored["composite_score"] <= 100

    def test_critical_finding_scores_high(self, full_state):
        # Inject a finding that should score very high
        full_state["scan_results"] = [{
            "finding_id": "f-crit",
            "asset_id": full_state["discovered_assets"][0]["asset_id"],
            "severity": "critical",
            "cvss_score": 10.0,
            "epss_score": 0.95,
            "in_kev": True,
            "title": "Critical vuln",
        }]
        full_state["validated_exploits"] = [{
            "exploit_id": "e-crit",
            "finding_id": "f-crit",
            "success": True,
        }]
        full_state["discovered_assets"][0]["criticality"] = "critical"

        result = score_and_prioritize(full_state)
        scores = result["risk_scores"]
        assert len(scores) == 1
        assert scores[0]["composite_score"] >= 80

    def test_info_finding_scores_low(self, full_state):
        full_state["scan_results"] = [{
            "finding_id": "f-info",
            "asset_id": full_state["discovered_assets"][0]["asset_id"],
            "severity": "info",
            "cvss_score": 0.0,
            "epss_score": 0.01,
            "in_kev": False,
            "title": "Info disclosure",
        }]
        full_state["validated_exploits"] = []

        result = score_and_prioritize(full_state)
        scores = result["risk_scores"]
        assert scores[0]["composite_score"] < 30

    def test_empty_findings(self, full_state):
        full_state["scan_results"] = []
        result = score_and_prioritize(full_state)
        assert result.get("risk_scores", []) == []

    def test_score_has_components(self, full_state):
        result = score_and_prioritize(full_state)
        for scored in result.get("risk_scores", []):
            assert "cvss_component" in scored
            assert "epss_component" in scored
            assert "exploit_component" in scored
            assert "criticality_component" in scored
            assert "exposure_component" in scored
