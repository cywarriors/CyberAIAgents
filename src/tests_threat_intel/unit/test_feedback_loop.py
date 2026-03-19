"""Unit tests for nodes/feedback_loop.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import generate_commercial_intel_record


def _state_with(distribution_results=None, briefs=None):
    return {
        "raw_intel": [],
        "normalized_objects": [],
        "deduplicated_iocs": [],
        "confidence_scores": [],
        "relevance_assessments": [],
        "attck_mappings": [],
        "briefs": briefs or [],
        "distribution_results": distribution_results or [],
        "feedback_results": [],
        "processing_errors": [],
    }


class TestFeedbackLoop:
    def test_feedback_results_returned(self):
        from threat_intelligence_agent.nodes.feedback_loop import feedback_loop
        dist = [{"ioc_id": "abc", "distributed": True, "destinations": ["siem"]}]
        result = feedback_loop(_state_with(distribution_results=dist))
        assert "feedback_results" in result

    def test_empty_inputs_returns_empty_feedback(self):
        from threat_intelligence_agent.nodes.feedback_loop import feedback_loop
        result = feedback_loop(_state_with())
        assert result["feedback_results"] == []

    def test_feedback_has_timestamp(self):
        from threat_intelligence_agent.nodes.feedback_loop import feedback_loop
        dist = [{"ioc_id": "xyz", "distributed": True, "destinations": ["edr"]}]
        result = feedback_loop(_state_with(distribution_results=dist))
        if result["feedback_results"]:
            fb = result["feedback_results"][0]
            has_ts = any(k in fb for k in ("timestamp", "processed_at", "updated_at"))
            assert has_ts

    def test_no_processing_errors_on_valid_input(self):
        from threat_intelligence_agent.nodes.feedback_loop import feedback_loop
        dist = [{"ioc_id": "def", "distributed": False, "reason": "low_confidence"}]
        result = feedback_loop(_state_with(distribution_results=dist))
        assert result.get("processing_errors", []) == []

    def test_feedback_with_briefs(self):
        from threat_intelligence_agent.nodes.feedback_loop import feedback_loop
        briefs = [{"id": "brief-1", "level": "tactical", "summary": "Test brief"}]
        result = feedback_loop(_state_with(briefs=briefs))
        assert isinstance(result["feedback_results"], list)
