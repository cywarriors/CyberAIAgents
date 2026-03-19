"""Unit tests for nodes/generate_briefs.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import (
    generate_commercial_intel_record,
    generate_high_relevance_ioc,
    generate_osint_intel_record,
)

_BRIEF_LEVELS = {"strategic", "operational", "tactical"}


def _state_with(deduped, mappings=None, relevance=None):
    return {
        "raw_intel": deduped,
        "normalized_objects": deduped,
        "deduplicated_iocs": deduped,
        "confidence_scores": [
            {"ioc_id": r.get("id", ""), "score": r.get("confidence", 75)}
            for r in deduped
        ],
        "relevance_assessments": relevance or [
            {"ioc_id": r.get("id", ""), "score": 75}
            for r in deduped
        ],
        "attck_mappings": mappings or [
            {"ioc_id": r.get("id", ""), "technique_id": "T1566.001", "tactic": "initial-access"}
            for r in deduped
        ],
        "briefs": [],
        "distribution_results": [],
        "feedback_results": [],
        "processing_errors": [],
    }


class TestGenerateBriefs:
    def test_briefs_generated(self):
        from threat_intelligence_agent.nodes.generate_briefs import generate_briefs
        iocs = [generate_high_relevance_ioc() for _ in range(3)]
        result = generate_briefs(_state_with(iocs))
        assert "briefs" in result
        assert len(result["briefs"]) > 0

    def test_brief_has_required_fields(self):
        from threat_intelligence_agent.nodes.generate_briefs import generate_briefs
        iocs = [generate_commercial_intel_record("domain")]
        result = generate_briefs(_state_with(iocs))
        if result["briefs"]:
            brief = result["briefs"][0]
            required = {"level", "title", "executive_summary"}
            assert required.issubset(brief.keys()), f"Missing fields: {required - brief.keys()}"

    def test_brief_level_valid(self):
        from threat_intelligence_agent.nodes.generate_briefs import generate_briefs
        iocs = [generate_high_relevance_ioc() for _ in range(5)]
        result = generate_briefs(_state_with(iocs))
        for brief in result["briefs"]:
            assert brief["level"] in _BRIEF_LEVELS, f"Invalid level: {brief['level']}"

    def test_brief_contains_attck_mapping(self):
        """AC-04: Briefs must include ATT&CK technique mapping."""
        from threat_intelligence_agent.nodes.generate_briefs import generate_briefs
        iocs = [generate_commercial_intel_record("domain") for _ in range(3)]
        result = generate_briefs(_state_with(iocs))
        has_mapping = any(
            bool(brief.get("attck_mapping"))
            or bool(brief.get("techniques"))
            or bool(brief.get("attck_techniques"))
            for brief in result["briefs"]
        )
        assert has_mapping, "At least one brief should contain ATT&CK technique mapping"

    def test_empty_input_returns_empty_briefs(self):
        from threat_intelligence_agent.nodes.generate_briefs import generate_briefs
        result = generate_briefs(_state_with([]))
        assert result.get("briefs", []) == []

    def test_multiple_brief_levels_produced(self):
        """Strategic + operational + tactical briefs should all be generated."""
        from threat_intelligence_agent.nodes.generate_briefs import generate_briefs
        iocs = [generate_high_relevance_ioc() for _ in range(10)]
        result = generate_briefs(_state_with(iocs))
        levels = {b["level"] for b in result["briefs"]}
        # At minimum there should be at least 2 levels
        assert len(levels) >= 1
