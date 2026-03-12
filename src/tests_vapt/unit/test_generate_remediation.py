"""Unit tests for Node 7 – GenerateRemediation."""

from __future__ import annotations

import pytest
from vapt_agent.nodes.generate_remediation import generate_remediation


class TestGenerateRemediation:
    """Test suite for remediation generation node."""

    def test_generates_remediation_per_scored_finding(self, full_state):
        # First score the findings
        from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
        scored_state = {**full_state, **score_and_prioritize(full_state)}
        result = generate_remediation(scored_state)
        items = result.get("remediation_items", [])
        assert len(items) == len(scored_state["risk_scores"])

    def test_remediation_has_guidance(self, full_state):
        from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
        scored_state = {**full_state, **score_and_prioritize(full_state)}
        result = generate_remediation(scored_state)
        for item in result.get("remediation_items", []):
            assert item.get("guidance")
            assert len(item["guidance"]) > 0

    def test_cwe_specific_guidance(self):
        """Findings with known CWE IDs get template-based guidance."""
        state = {
            "risk_scores": [{
                "finding_id": "f1",
                "asset_id": "a1",
                "composite_score": 90,
                "severity": "critical",
                "title": "SQL Injection",
                "cve_id": "CVE-2023-12345",
            }],
            "scan_results": [{
                "finding_id": "f1",
                "cwe_id": "CWE-89",
                "title": "SQL Injection",
            }],
        }
        result = generate_remediation(state)
        items = result["remediation_items"]
        assert "parameterised" in items[0]["guidance"].lower() or "prepared" in items[0]["guidance"].lower()

    def test_priority_labels(self):
        state = {
            "risk_scores": [
                {"finding_id": "f1", "asset_id": "a1", "composite_score": 90, "severity": "critical", "title": "A"},
                {"finding_id": "f2", "asset_id": "a1", "composite_score": 65, "severity": "high", "title": "B"},
                {"finding_id": "f3", "asset_id": "a1", "composite_score": 45, "severity": "medium", "title": "C"},
                {"finding_id": "f4", "asset_id": "a1", "composite_score": 15, "severity": "low", "title": "D"},
            ],
            "scan_results": [],
        }
        result = generate_remediation(state)
        items = result["remediation_items"]
        assert items[0]["priority"] == "P1-Immediate"
        assert items[1]["priority"] == "P2-Urgent"
        assert items[2]["priority"] == "P3-Moderate"
        assert items[3]["priority"] == "P4-Low"

    def test_empty_scores(self):
        result = generate_remediation({"risk_scores": [], "scan_results": []})
        assert result.get("remediation_items", []) == []
