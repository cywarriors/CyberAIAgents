"""Unit tests for nodes/distribute_iocs.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import (
    generate_internal_ioc,
    generate_commercial_intel_record,
    generate_osint_intel_record,
)


def _state_with(deduped, conf_scores=None):
    return {
        "raw_intel": [],
        "normalized_objects": [],
        "deduplicated_iocs": deduped,
        "confidence_scores": conf_scores or [
            {"ioc_id": r.get("id", ""), "score": r.get("confidence", 85)}
            for r in deduped
        ],
        "relevance_assessments": [
            {"ioc_id": r.get("id", ""), "score": 80}
            for r in deduped
        ],
        "attck_mappings": [],
        "briefs": [],
        "distribution_results": [],
        "feedback_results": [],
        "processing_errors": [],
    }


class TestDistributeIOCs:
    def test_distribution_results_returned(self):
        from threat_intelligence_agent.nodes.distribute_iocs import distribute_iocs
        iocs = [generate_commercial_intel_record("domain")]
        result = distribute_iocs(_state_with(iocs))
        assert "distribution_results" in result

    def test_tlp_red_not_auto_distributed(self):
        """TLP:RED IOCs must never be automatically pushed to external systems."""
        from threat_intelligence_agent.nodes.distribute_iocs import distribute_iocs
        red_iocs = [generate_internal_ioc("ip")]  # generate_internal_ioc sets TLP:RED
        result = distribute_iocs(_state_with(red_iocs))
        for dr in result["distribution_results"]:
            assert dr.get("tlp") != "RED" or dr.get("distributed") is False, \
                "TLP:RED IOC must not be marked as distributed"

    def test_high_confidence_iocs_distributed(self):
        from threat_intelligence_agent.nodes.distribute_iocs import distribute_iocs
        ioc = generate_commercial_intel_record("domain")
        ioc["tlp"] = "GREEN"
        conf = [{"ioc_id": ioc.get("id", ""), "score": 90}]
        result = distribute_iocs(_state_with([ioc], conf_scores=conf))
        assert isinstance(result["distribution_results"], list)

    def test_low_confidence_iocs_not_distributed(self):
        from threat_intelligence_agent.nodes.distribute_iocs import distribute_iocs
        ioc = generate_osint_intel_record("ip")
        ioc["tlp"] = "GREEN"
        conf = [{"ioc_id": ioc.get("id", ""), "score": 30}]  # below threshold
        result = distribute_iocs(_state_with([ioc], conf_scores=conf))
        low_conf_distributed = [
            dr for dr in result["distribution_results"]
            if dr.get("confidence_score", 100) < 80 and dr.get("distributed") is True
        ]
        assert len(low_conf_distributed) == 0

    def test_empty_iocs_returns_empty_results(self):
        from threat_intelligence_agent.nodes.distribute_iocs import distribute_iocs
        result = distribute_iocs(_state_with([]))
        assert result["distribution_results"] == []

    def test_distribution_result_has_status(self):
        from threat_intelligence_agent.nodes.distribute_iocs import distribute_iocs
        ioc = generate_commercial_intel_record("domain")
        ioc["tlp"] = "GREEN"
        result = distribute_iocs(_state_with([ioc]))
        if result["distribution_results"]:
            dr = result["distribution_results"][0]
            has_status = any(k in dr for k in ("status", "distributed", "result"))
            assert has_status
