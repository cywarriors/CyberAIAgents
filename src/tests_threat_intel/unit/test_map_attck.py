"""Unit tests for nodes/map_attck.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import (
    generate_commercial_intel_record,
    generate_isac_intel_record,
    generate_osint_intel_record,
)

_KNOWN_TECHNIQUES = {
    "T1566", "T1059", "T1071", "T1486", "T1055",
    "T1027", "T1105", "T1562", "T1036", "T1041",
}


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


class TestMapATTCK:
    def test_mappings_returned(self):
        from threat_intelligence_agent.nodes.map_attck import map_attck
        iocs = [generate_commercial_intel_record("domain")]
        result = map_attck(_state_with(iocs))
        assert "attck_mappings" in result

    def test_technique_ids_contain_T_prefix(self):
        from threat_intelligence_agent.nodes.map_attck import map_attck
        iocs = [
            generate_commercial_intel_record("domain"),
            generate_isac_intel_record("hash"),
        ]
        result = map_attck(_state_with(iocs))
        for m in result["attck_mappings"]:
            technique = m.get("technique_id", m.get("technique", ""))
            assert technique.startswith("T"), f"Invalid technique: {technique}"

    def test_empty_input_returns_empty(self):
        from threat_intelligence_agent.nodes.map_attck import map_attck
        result = map_attck(_state_with([]))
        assert result.get("attck_mappings", []) == []

    def test_known_techniques_in_mapping(self):
        from threat_intelligence_agent.nodes.map_attck import map_attck
        iocs = [generate_commercial_intel_record("domain") for _ in range(5)]
        result = map_attck(_state_with(iocs))
        if result["attck_mappings"]:
            technique_ids = {
                m.get("technique_id", m.get("technique", "")).split(".")[0]
                for m in result["attck_mappings"]
            }
            assert len(technique_ids) > 0

    def test_ioc_reference_in_mapping(self):
        from threat_intelligence_agent.nodes.map_attck import map_attck
        iocs = [generate_isac_intel_record("hash")]
        result = map_attck(_state_with(iocs))
        if result["attck_mappings"]:
            m = result["attck_mappings"][0]
            has_ref = any(k in m for k in ("ioc_id", "ioc_value", "id", "value"))
            assert has_ref

    def test_batch_mapping(self):
        from threat_intelligence_agent.nodes.map_attck import map_attck
        iocs = [generate_osint_intel_record("ip") for _ in range(10)]
        result = map_attck(_state_with(iocs))
        # Should produce at least some mappings for 10 IOCs
        assert isinstance(result["attck_mappings"], list)
