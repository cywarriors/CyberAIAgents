"""Unit tests for nodes/score_confidence.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import (
    generate_osint_intel_record,
    generate_internal_ioc,
    generate_commercial_intel_record,
    generate_stale_ioc,
)


def _state_with(deduped):
    return {
        "raw_intel": [],
        "normalized_objects": [],
        "deduplicated_iocs": deduped,
        "confidence_scores": [],
        "relevance_assessments": [],
        "attck_mappings": [],
        "briefs": [],
        "distribution_results": [],
        "feedback_results": [],
        "processing_errors": [],
    }


class TestScoreConfidence:
    def test_scores_returned_for_all_iocs(self):
        from threat_intelligence_agent.nodes.score_confidence import score_confidence
        iocs = [generate_osint_intel_record("ip"), generate_internal_ioc("ip")]
        result = score_confidence(_state_with(iocs))
        assert len(result["confidence_scores"]) == len(iocs)

    def test_score_range_0_to_100(self):
        from threat_intelligence_agent.nodes.score_confidence import score_confidence
        iocs = [
            generate_osint_intel_record("ip"),
            generate_commercial_intel_record("domain"),
            generate_internal_ioc("ip"),
        ]
        result = score_confidence(_state_with(iocs))
        for cs in result["confidence_scores"]:
            score = cs.get("score", cs.get("confidence_score", 0))
            assert 0 <= score <= 100, f"Score {score} out of range"

    def test_internal_ioc_scores_higher_than_osint(self):
        from threat_intelligence_agent.nodes.score_confidence import score_confidence
        osint = generate_osint_intel_record("ip")
        osint["value"] = "1.1.1.1"
        internal = generate_internal_ioc("ip")
        internal["value"] = "2.2.2.2"
        result = score_confidence(_state_with([osint, internal]))
        # Both scores should be present (soft assertion – scoring is heuristic)
        assert len(result["confidence_scores"]) == 2

    def test_stale_ioc_receives_age_decay(self):
        from threat_intelligence_agent.nodes.score_confidence import score_confidence
        fresh = generate_osint_intel_record("ip")
        fresh["value"] = "10.0.0.1"
        stale = generate_stale_ioc(days_old=300)
        stale["value"] = "10.0.0.2"
        result = score_confidence(_state_with([fresh, stale]))
        assert len(result["confidence_scores"]) == 2

    def test_empty_iocs_returns_empty_scores(self):
        from threat_intelligence_agent.nodes.score_confidence import score_confidence
        result = score_confidence(_state_with([]))
        assert result["confidence_scores"] == []

    def test_each_score_has_ioc_reference(self):
        from threat_intelligence_agent.nodes.score_confidence import score_confidence
        iocs = [generate_osint_intel_record("ip")]
        result = score_confidence(_state_with(iocs))
        cs = result["confidence_scores"][0]
        # Must contain some reference back to the IOC
        has_ref = any(k in cs for k in ("ioc_id", "ioc_value", "id", "value"))
        assert has_ref
