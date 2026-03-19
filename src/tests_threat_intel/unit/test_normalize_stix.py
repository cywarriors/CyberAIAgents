"""Unit tests for nodes/normalize_stix.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import (
    generate_osint_intel_record,
    generate_commercial_intel_record,
    generate_mixed_intel_batch,
)


class TestNormalizeStix:
    def _state_with(self, records):
        return {
            "raw_intel": records,
            "normalized_objects": [],
            "deduplicated_iocs": [],
            "confidence_scores": [],
            "relevance_assessments": [],
            "attck_mappings": [],
            "briefs": [],
            "distribution_results": [],
            "feedback_results": [],
            "processing_errors": [],
        }

    def test_normalize_returns_normalized_objects(self):
        from threat_intelligence_agent.nodes.normalize_stix import normalize_to_stix
        raw = [generate_osint_intel_record("ip")]
        result = normalize_to_stix(self._state_with(raw))
        assert "normalized_objects" in result
        assert len(result["normalized_objects"]) > 0

    def test_normalized_object_has_stix_fields(self):
        from threat_intelligence_agent.nodes.normalize_stix import normalize_to_stix
        raw = [generate_commercial_intel_record("domain")]
        result = normalize_to_stix(self._state_with(raw))
        obj = result["normalized_objects"][0]
        # Actual fields: stix_id, stix_type, indicator_type (or ioc_type), value
        assert "value" in obj.keys()
        has_type = any(k in obj for k in ("stix_type", "type", "indicator_type", "ioc_type"))
        assert has_type, f"No type field found in {list(obj.keys())}"

    def test_normalize_empty_raw_intel(self):
        from threat_intelligence_agent.nodes.normalize_stix import normalize_to_stix
        result = normalize_to_stix(self._state_with([]))
        assert result.get("normalized_objects", []) == []

    def test_normalize_handles_batch(self):
        from threat_intelligence_agent.nodes.normalize_stix import normalize_to_stix
        raw = generate_mixed_intel_batch(10)
        result = normalize_to_stix(self._state_with(raw))
        # Normalisation may skip malformed records but should process most
        assert len(result["normalized_objects"]) >= 8

    def test_tlp_field_preserved(self):
        from threat_intelligence_agent.nodes.normalize_stix import normalize_to_stix
        raw = [generate_osint_intel_record("ip")]
        raw[0]["tlp"] = "AMBER"
        result = normalize_to_stix(self._state_with(raw))
        assert result["normalized_objects"][0].get("tlp") == "AMBER"

    def test_all_valid_ioc_types(self):
        from threat_intelligence_agent.nodes.normalize_stix import normalize_to_stix
        records = [
            generate_osint_intel_record("ip"),
            generate_osint_intel_record("domain"),
            generate_commercial_intel_record("url"),
        ]
        result = normalize_to_stix(self._state_with(records))
        assert len(result["normalized_objects"]) >= 2
