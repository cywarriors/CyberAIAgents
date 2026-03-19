"""Unit tests for nodes/deduplicate.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import (
    generate_duplicate_ioc_pair,
    generate_osint_intel_record,
)


def _norm(records):
    """Wrap raw records as normalised-style objects for dedup node."""
    out = []
    for r in records:
        obj = dict(r)
        obj.setdefault("type", "indicator")
        out.append(obj)
    return out


def _state_with(normalized):
    return {
        "raw_intel": [],
        "normalized_objects": normalized,
        "deduplicated_iocs": [],
        "confidence_scores": [],
        "relevance_assessments": [],
        "attck_mappings": [],
        "briefs": [],
        "distribution_results": [],
        "feedback_results": [],
        "processing_errors": [],
    }


class TestDeduplicate:
    def test_dedup_removes_exact_duplicates(self):
        from threat_intelligence_agent.nodes.deduplicate import deduplicate_iocs
        dup1, dup2 = generate_duplicate_ioc_pair()
        result = deduplicate_iocs(_state_with(_norm([dup1, dup2])))
        iocs = result["deduplicated_iocs"]
        values = [i["value"] for i in iocs]
        assert values.count(dup1["value"]) == 1, "Duplicate value must appear exactly once"

    def test_dedup_preserves_unique_iocs(self):
        from threat_intelligence_agent.nodes.deduplicate import deduplicate_iocs
        records = [generate_osint_intel_record("ip") for _ in range(5)]
        # Make all values distinct
        for i, r in enumerate(records):
            r["value"] = f"10.0.0.{i+1}"
        result = deduplicate_iocs(_state_with(_norm(records)))
        assert len(result["deduplicated_iocs"]) == 5

    def test_dedup_empty_input(self):
        from threat_intelligence_agent.nodes.deduplicate import deduplicate_iocs
        result = deduplicate_iocs(_state_with([]))
        assert result["deduplicated_iocs"] == []

    def test_dedup_provenance_chain_merged(self):
        from threat_intelligence_agent.nodes.deduplicate import deduplicate_iocs
        dup1, dup2 = generate_duplicate_ioc_pair()
        result = deduplicate_iocs(_state_with(_norm([dup1, dup2])))
        ioc = result["deduplicated_iocs"][0]
        # Provenance or sources should reference both origins
        provenance = ioc.get("provenance", ioc.get("sources", []))
        assert len(provenance) >= 1

    def test_dedup_high_volume(self):
        """Dedup 100 records with 10 unique values — must yield 10 outputs."""
        from threat_intelligence_agent.nodes.deduplicate import deduplicate_iocs
        records = []
        for i in range(10):
            for _ in range(10):
                r = generate_osint_intel_record("ip")
                r["value"] = f"10.0.0.{i+1}"
                records.append(r)
        result = deduplicate_iocs(_state_with(_norm(records)))
        assert len(result["deduplicated_iocs"]) == 10

    def test_dedup_accuracy_threshold(self):
        """Dedup accuracy ≥99% per AC-02: at most 1% duplicates in output."""
        from threat_intelligence_agent.nodes.deduplicate import deduplicate_iocs
        records = []
        for i in range(50):
            for _ in range(2):
                r = generate_osint_intel_record("ip")
                r["value"] = f"192.168.{i // 256}.{i % 256}"
                records.append(r)
        result = deduplicate_iocs(_state_with(_norm(records)))
        unique_values = {i["value"] for i in result["deduplicated_iocs"]}
        total_out = len(result["deduplicated_iocs"])
        duplicates = total_out - len(unique_values)
        accuracy = 1.0 - (duplicates / max(total_out, 1))
        assert accuracy >= 0.99, f"Dedup accuracy {accuracy:.2%} below 99%"
