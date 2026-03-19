"""Unit tests for nodes/assess_relevance.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import (
    generate_high_relevance_ioc,
    generate_low_relevance_ioc,
    generate_osint_intel_record,
)


def _state_with(scored_iocs, conf_scores=None):
    return {
        "raw_intel": [],
        "normalized_objects": [],
        "deduplicated_iocs": scored_iocs,
        "confidence_scores": conf_scores or [],
        "relevance_assessments": [],
        "attck_mappings": [],
        "briefs": [],
        "distribution_results": [],
        "feedback_results": [],
        "processing_errors": [],
    }


class TestAssessRelevance:
    def test_relevance_returned_for_each_ioc(self):
        from threat_intelligence_agent.nodes.assess_relevance import assess_relevance
        iocs = [generate_osint_intel_record("ip"), generate_high_relevance_ioc()]
        result = assess_relevance(_state_with(iocs))
        assert len(result["relevance_assessments"]) == len(iocs)

    def test_relevance_score_range_0_to_100(self):
        from threat_intelligence_agent.nodes.assess_relevance import assess_relevance
        iocs = [generate_high_relevance_ioc(), generate_low_relevance_ioc()]
        result = assess_relevance(_state_with(iocs))
        for ra in result["relevance_assessments"]:
            score = ra.get("score", ra.get("relevance_score", 50))
            assert 0 <= score <= 100

    def test_high_relevance_ioc_scores_above_50(self):
        from threat_intelligence_agent.nodes.assess_relevance import assess_relevance
        iocs = [generate_high_relevance_ioc("financial")]
        result = assess_relevance(_state_with(iocs))
        ra = result["relevance_assessments"][0]
        score = ra.get("score", ra.get("relevance_score", 50))
        assert score >= 50, f"High-relevance IOC scored only {score}"

    def test_empty_input_returns_empty(self):
        from threat_intelligence_agent.nodes.assess_relevance import assess_relevance
        result = assess_relevance(_state_with([]))
        assert result["relevance_assessments"] == []

    def test_assessment_has_ioc_reference(self):
        from threat_intelligence_agent.nodes.assess_relevance import assess_relevance
        iocs = [generate_osint_intel_record("ip")]
        result = assess_relevance(_state_with(iocs))
        ra = result["relevance_assessments"][0]
        has_ref = any(k in ra for k in ("ioc_id", "id", "value", "ioc_value"))
        assert has_ref

    def test_batch_assessment(self):
        from threat_intelligence_agent.nodes.assess_relevance import assess_relevance
        iocs = [generate_osint_intel_record("ip") for _ in range(20)]
        result = assess_relevance(_state_with(iocs))
        assert len(result["relevance_assessments"]) == 20
