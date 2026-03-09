"""Unit tests for DeduplicateNode."""

import pytest
from threat_detection_agent.nodes.deduplicate import deduplicate, reset_dedup_cache


class TestDeduplicate:
    def test_first_candidate_passes_through(self):
        candidate = {
            "candidate_id": "c1",
            "mitre_technique_ids": ["T1110"],
            "entity_ids": ["alice"],
            "severity": "High",
        }
        result = deduplicate({"alert_candidates": [candidate]})
        assert len(result["alert_candidates"]) == 1

    def test_duplicate_candidate_suppressed(self):
        candidate = {
            "candidate_id": "c1",
            "mitre_technique_ids": ["T1110"],
            "entity_ids": ["alice"],
            "severity": "High",
        }
        # First pass
        deduplicate({"alert_candidates": [candidate]})
        # Second pass – same key → suppressed
        result = deduplicate({"alert_candidates": [{**candidate, "candidate_id": "c2"}]})
        assert len(result["alert_candidates"]) == 0

    def test_different_entities_not_suppressed(self):
        c1 = {
            "candidate_id": "c1",
            "mitre_technique_ids": ["T1110"],
            "entity_ids": ["alice"],
            "severity": "High",
        }
        c2 = {
            "candidate_id": "c2",
            "mitre_technique_ids": ["T1110"],
            "entity_ids": ["bob"],
            "severity": "High",
        }
        deduplicate({"alert_candidates": [c1]})
        result = deduplicate({"alert_candidates": [c2]})
        assert len(result["alert_candidates"]) == 1

    def test_empty_input(self):
        result = deduplicate({"alert_candidates": []})
        assert result["alert_candidates"] == []
