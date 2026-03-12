"""Integration tests – full VAPT pipeline execution.

Exercises the entire LangGraph pipeline end-to-end by injecting mock data
into the state and running all 9 nodes sequentially.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from vapt_agent.nodes.validate_roe import validate_roe
from vapt_agent.nodes.discover_assets import discover_assets
from vapt_agent.nodes.scan_vulnerabilities import scan_vulnerabilities
from vapt_agent.nodes.validate_exploits import validate_exploits
from vapt_agent.nodes.analyze_attack_paths import analyze_attack_paths
from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
from vapt_agent.nodes.generate_remediation import generate_remediation
from vapt_agent.nodes.generate_report import generate_report
from vapt_agent.nodes.publish_findings import publish_findings
from tests_vapt.mocks.generators import (
    build_engagement_state,
    generate_valid_roe,
    generate_discovered_assets,
    generate_scan_findings,
    generate_benign_findings,
)


def _merge(base: dict, update: dict) -> dict:
    """Merge state update into base (append to lists)."""
    merged = dict(base)
    for key, val in update.items():
        if isinstance(val, list) and isinstance(merged.get(key), list):
            merged[key] = merged[key] + val
        else:
            merged[key] = val
    return merged


def _run_pipeline(initial_state: dict[str, Any]) -> dict[str, Any]:
    """Execute the full 9-node pipeline sequentially with mocked integrations."""
    state = dict(initial_state)

    # Node 1: ValidateRoE
    state = _merge(state, validate_roe(state))
    if not state.get("roe_validated"):
        return state

    # Node 2: DiscoverAssets (skip real nmap – assets already injected)
    # Use injected assets from state rather than calling scanners
    if not state.get("discovered_assets"):
        with patch("vapt_agent.nodes.discover_assets.run_nmap_scan", return_value=[]):
            state = _merge(state, discover_assets(state))

    # Node 3: ScanVulnerabilities (skip real scanners – findings injected)
    if not state.get("scan_results"):
        with patch("vapt_agent.nodes.scan_vulnerabilities.run_nuclei_scan", return_value=[]), \
             patch("vapt_agent.nodes.scan_vulnerabilities.run_nessus_scan", return_value=[]), \
             patch("vapt_agent.nodes.scan_vulnerabilities.run_zap_scan", return_value=[]):
            state = _merge(state, scan_vulnerabilities(state))

    # Node 4: ValidateExploits
    state = _merge(state, validate_exploits(state))

    # Node 5: AnalyzeAttackPaths
    state = _merge(state, analyze_attack_paths(state))

    # Node 6: ScoreAndPrioritize
    state = _merge(state, score_and_prioritize(state))

    # Node 7: GenerateRemediation
    state = _merge(state, generate_remediation(state))

    # Node 8: GenerateReport
    state = _merge(state, generate_report(state))

    # Node 9: PublishFindings
    with patch("vapt_agent.nodes.publish_findings.create_ticket", return_value="TKT-MOCK"), \
         patch("vapt_agent.nodes.publish_findings.send_notification", return_value=True):
        state = _merge(state, publish_findings(state))

    return state


class TestFullPipeline:
    """End-to-end pipeline integration tests."""

    def test_full_engagement_with_findings(self):
        """Pipeline processes a full engagement with mixed findings."""
        state = build_engagement_state(asset_count=3, finding_count=8)
        result = _run_pipeline(state)

        assert result["roe_validated"] is True
        assert len(result["risk_scores"]) == 8
        assert len(result["remediation_items"]) == 8
        assert len(result["report_artifacts"]) == 3
        assert len(result["published_findings"]) == 8

    def test_benign_only_engagement(self):
        """Pipeline handles an engagement with only informational findings."""
        roe = generate_valid_roe()
        assets = generate_discovered_assets(2)
        findings = generate_benign_findings(assets, count=3)

        state = {
            "engagement_id": "eng-benign",
            "roe_authorization": roe,
            "roe_validated": False,
            "discovered_assets": assets,
            "scan_results": findings,
            "validated_exploits": [],
            "attack_paths": [],
            "risk_scores": [],
            "remediation_items": [],
            "report_artifacts": [],
            "published_findings": [],
            "errors": [],
        }

        result = _run_pipeline(state)
        assert result["roe_validated"] is True
        # All info-level findings should still be scored
        assert len(result["risk_scores"]) == 3
        # All scores should be low
        for scored in result["risk_scores"]:
            assert scored["composite_score"] < 50

    def test_pipeline_aborts_without_roe(self):
        """Pipeline stops early if RoE is missing."""
        result = _run_pipeline({
            "roe_authorization": {},
            "discovered_assets": [],
            "scan_results": [],
            "validated_exploits": [],
            "attack_paths": [],
            "risk_scores": [],
            "remediation_items": [],
            "report_artifacts": [],
            "published_findings": [],
            "errors": [],
        })
        assert result["roe_validated"] is False
        assert result.get("risk_scores", []) == []

    def test_report_artifacts_content(self):
        """Report artifacts contain expected structure."""
        state = build_engagement_state(asset_count=2, finding_count=4)
        result = _run_pipeline(state)

        artifacts = result["report_artifacts"]
        exec_report = next(a for a in artifacts if a["report_type"] == "executive")
        assert exec_report["content"]["total_findings"] == 4

        tech_report = next(a for a in artifacts if a["report_type"] == "technical")
        assert len(tech_report["content"]["findings"]) == 4

        compliance = next(a for a in artifacts if a["report_type"] == "compliance")
        assert "findings_by_category" in compliance["content"]

    def test_remediation_priority_ordering(self):
        """Higher-scored findings get higher-priority remediation."""
        state = build_engagement_state(asset_count=3, finding_count=8)
        result = _run_pipeline(state)

        items = result["remediation_items"]
        # First item should have highest composite score
        if len(items) >= 2:
            assert items[0]["composite_score"] >= items[-1]["composite_score"]

    def test_published_findings_have_tickets(self):
        """Published findings should have ticket IDs from the mocked ticketing."""
        state = build_engagement_state(asset_count=2, finding_count=3)
        result = _run_pipeline(state)

        for pub in result["published_findings"]:
            assert pub.get("ticket_id") == "TKT-MOCK"
            assert "published_at" in pub
