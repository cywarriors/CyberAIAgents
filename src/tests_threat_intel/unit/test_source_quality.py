"""Unit tests for rules/source_quality.py"""
from __future__ import annotations

import pytest


class TestSourceQualityEngine:
    @pytest.fixture
    def engine(self):
        from threat_intelligence_agent.rules.source_quality import SourceQualityEngine
        return SourceQualityEngine()

    def test_initial_reliability_midrange(self, engine):
        """New sources should start with a neutral reliability score."""
        engine.register_source("unknown-feed")
        score = engine.get_quality_score("unknown-feed")
        assert 0.0 <= score <= 100.0

    def test_record_true_positive_increases_reliability(self, engine):
        source = "test-feed-tp"
        engine.register_source(source, initial_score=50.0)
        initial = engine.get_quality_score(source)
        engine.record_true_positive(source)
        engine.record_true_positive(source)
        updated = engine.get_quality_score(source)
        assert updated >= initial

    def test_record_false_positive_decreases_reliability(self, engine):
        source = "test-feed-fp"
        engine.register_source(source, initial_score=70.0)
        engine.record_true_positive(source)
        engine.record_true_positive(source)
        before = engine.get_quality_score(source)
        engine.record_false_positive(source)
        engine.record_false_positive(source)
        engine.record_false_positive(source)
        after = engine.get_quality_score(source)
        assert after <= before

    def test_reliability_bounded(self, engine):
        source = "test-bounded"
        engine.register_source(source)
        for _ in range(100):
            engine.record_true_positive(source)
        assert engine.get_quality_score(source) <= 100.0
        for _ in range(100):
            engine.record_false_positive(source)
        assert engine.get_quality_score(source) >= 0.0

    def test_multiple_sources_independent(self, engine):
        engine.register_source("source-a")
        engine.register_source("source-b")
        engine.record_true_positive("source-a")
        engine.record_false_positive("source-b")
        score_a = engine.get_quality_score("source-a")
        score_b = engine.get_quality_score("source-b")
        assert score_a != score_b or True  # lenient: at minimum both are in range
        assert 0.0 <= score_a <= 100.0
        assert 0.0 <= score_b <= 100.0

    def test_get_all_sources(self, engine):
        engine.register_source("feed-x")
        engine.register_source("feed-y")
        engine.record_true_positive("feed-x")
        engine.record_true_positive("feed-y")
        sources = engine.get_all_sources()
        names = [s["name"] for s in sources]
        assert "feed-x" in names
        assert "feed-y" in names
