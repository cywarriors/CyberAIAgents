"""Unit tests for Node 8 – GenerateReport."""

from __future__ import annotations

import pytest
from vapt_agent.nodes.generate_report import generate_report


class TestGenerateReport:
    """Test suite for report generation node."""

    def test_generates_three_report_types(self, full_state):
        from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
        from vapt_agent.nodes.generate_remediation import generate_remediation
        scored_state = {**full_state, **score_and_prioritize(full_state)}
        remed_state = {**scored_state, **generate_remediation(scored_state)}

        result = generate_report(remed_state)
        artifacts = result.get("report_artifacts", [])
        assert len(artifacts) == 3

        types = {a["report_type"] for a in artifacts}
        assert types == {"executive", "technical", "compliance"}

    def test_executive_has_severity_breakdown(self, full_state):
        from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
        scored_state = {**full_state, **score_and_prioritize(full_state)}

        result = generate_report(scored_state)
        executive = next(
            a for a in result["report_artifacts"]
            if a["report_type"] == "executive"
        )
        content = executive["content"]
        assert "severity_breakdown" in content
        assert "total_findings" in content

    def test_compliance_has_owasp_mapping(self, full_state):
        from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
        scored_state = {**full_state, **score_and_prioritize(full_state)}

        result = generate_report(scored_state)
        compliance = next(
            a for a in result["report_artifacts"]
            if a["report_type"] == "compliance"
        )
        content = compliance["content"]
        assert content["framework"] == "OWASP Top 10 - 2021"
        assert "findings_by_category" in content

    def test_empty_findings(self):
        result = generate_report({
            "engagement_id": "eng-empty",
            "risk_scores": [],
            "remediation_items": [],
            "attack_paths": [],
            "discovered_assets": [],
            "validated_exploits": [],
        })
        artifacts = result["report_artifacts"]
        assert len(artifacts) == 3
        exec_content = next(
            a["content"] for a in artifacts if a["report_type"] == "executive"
        )
        assert exec_content["total_findings"] == 0
