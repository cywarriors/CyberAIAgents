"""Unit tests for Node 5 – AnalyzeAttackPaths."""

from __future__ import annotations

import pytest
from vapt_agent.nodes.analyze_attack_paths import analyze_attack_paths


class TestAnalyzeAttackPaths:
    """Test suite for attack path analysis node."""

    def test_builds_paths_from_exploits(self, full_state):
        result = analyze_attack_paths(full_state)
        paths = result.get("attack_paths", [])
        # Should have at least one path when there are successful exploits
        successful = [e for e in full_state["validated_exploits"] if e["success"]]
        if successful:
            assert len(paths) >= 1

    def test_no_exploits_returns_empty(self):
        result = analyze_attack_paths({
            "validated_exploits": [],
            "scan_results": [],
            "discovered_assets": [],
        })
        assert result.get("attack_paths", []) == []

    def test_no_successful_exploits_returns_empty(self, full_state):
        for exp in full_state["validated_exploits"]:
            exp["success"] = False
        result = analyze_attack_paths(full_state)
        assert result.get("attack_paths", []) == []

    def test_path_has_required_fields(self, full_state):
        result = analyze_attack_paths(full_state)
        paths = result.get("attack_paths", [])
        for path in paths:
            assert "path_id" in path
            assert "steps" in path
            assert "composite_risk" in path
            assert isinstance(path["steps"], list)

    def test_composite_risk_is_numeric(self, full_state):
        result = analyze_attack_paths(full_state)
        for path in result.get("attack_paths", []):
            assert isinstance(path["composite_risk"], (int, float))
