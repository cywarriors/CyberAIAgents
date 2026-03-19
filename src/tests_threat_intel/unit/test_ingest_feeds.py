"""Unit tests for nodes/ingest_feeds.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import generate_mixed_intel_batch


class TestIngestFeeds:
    def test_ingest_returns_raw_intel_list(self, empty_state):
        from threat_intelligence_agent.nodes.ingest_feeds import ingest_feeds
        result = ingest_feeds(empty_state)
        assert "raw_intel" in result
        assert isinstance(result["raw_intel"], list)

    def test_ingest_produces_nonempty_batch(self, empty_state):
        """With pre-seeded data ingest merges and returns records."""
        from threat_intelligence_agent.nodes.ingest_feeds import ingest_feeds
        # Pre-seed raw_intel so we always have records regardless of API keys
        empty_state["raw_intel"] = generate_mixed_intel_batch(5)
        result = ingest_feeds(empty_state)
        assert len(result["raw_intel"]) > 0

    def test_each_record_has_required_fields(self, empty_state):
        from threat_intelligence_agent.nodes.ingest_feeds import ingest_feeds
        result = ingest_feeds(empty_state)
        required = {"id", "source_type", "ioc_type", "value"}
        for rec in result["raw_intel"]:
            assert required.issubset(rec.keys()), f"Missing fields in {rec}"

    def test_ingest_graceful_on_empty_keys(self, empty_state):
        """With empty API keys the node must still return (mock data) without raising."""
        from threat_intelligence_agent.nodes.ingest_feeds import ingest_feeds
        result = ingest_feeds(empty_state)
        assert isinstance(result, dict)
        assert "raw_intel" in result

    def test_existing_raw_intel_preserved(self, empty_state):
        from threat_intelligence_agent.nodes.ingest_feeds import ingest_feeds
        prior = generate_mixed_intel_batch(3)
        empty_state["raw_intel"] = prior
        result = ingest_feeds(empty_state)
        # Merged list must contain at least what we injected
        assert len(result["raw_intel"]) >= len(prior)

    def test_no_processing_errors_on_clean_run(self, empty_state):
        from threat_intelligence_agent.nodes.ingest_feeds import ingest_feeds
        result = ingest_feeds(empty_state)
        assert result.get("processing_errors", []) == []
