"""Unit tests for rules/ioc_lifecycle.py"""
from __future__ import annotations

import pytest
from tests_threat_intel.mocks.generators import (
    generate_osint_intel_record,
    generate_stale_ioc,
)


class TestIOCLifecycleEngine:
    @pytest.fixture
    def engine(self):
        from threat_intelligence_agent.rules.ioc_lifecycle import IOCLifecycleEngine
        return IOCLifecycleEngine(max_age_days=180)

    def test_fresh_ioc_lifecycle_unchanged(self, engine):
        """Fresh IOC should not be deprecated."""
        ioc = generate_osint_intel_record("ip")
        ioc["lifecycle"] = "active"
        result = engine.evaluate([ioc])
        assert result[0]["lifecycle"] != "deprecated"

    def test_stale_ioc_lifecycle_deprecated(self, engine):
        """IOC older than max_age_days should be deprecated."""
        ioc = generate_stale_ioc(days_old=300)
        ioc["lifecycle"] = "active"
        result = engine.evaluate([ioc])
        assert result[0]["lifecycle"] == "deprecated", \
            f"Expected deprecated for 300-day-old IOC, got {result[0]['lifecycle']}"

    def test_revoke_ioc(self, engine):
        ioc = generate_osint_intel_record("ip")
        ioc["lifecycle"] = "active"
        revoked = engine.revoke(ioc, reason="false positive confirmed")
        assert revoked["lifecycle"] == "revoked"

    def test_revoked_ioc_preserved_in_evaluate(self, engine):
        """Revoked IOCs must not be altered by evaluate()."""
        ioc = generate_osint_intel_record("ip")
        ioc["lifecycle"] = "revoked"
        result = engine.evaluate([ioc])
        assert result[0]["lifecycle"] == "revoked"

    def test_reactivate_deprecated_ioc(self, engine):
        ioc = generate_stale_ioc(days_old=200)
        ioc["lifecycle"] = "deprecated"
        reactivated = engine.reactivate(ioc)
        assert reactivated["lifecycle"] == "active"

    def test_reactivate_revoked_ioc_no_effect(self, engine):
        """Reactivating a revoked IOC should not change it to active."""
        ioc = generate_osint_intel_record("ip")
        ioc["lifecycle"] = "revoked"
        result = engine.reactivate(ioc)
        assert result["lifecycle"] != "active"

    def test_lifecycle_threshold_default_180_days(self, engine):
        fresh = generate_osint_intel_record("ip")
        fresh["lifecycle"] = "active"
        stale = generate_stale_ioc(days_old=181)
        stale["lifecycle"] = "active"
        fresh_result = engine.evaluate([fresh])[0]
        assert fresh_result["lifecycle"] != "deprecated"
        stale_result = engine.evaluate([stale])[0]
        assert stale_result["lifecycle"] == "deprecated"

    def test_bulk_evaluate(self, engine):
        iocs = [generate_osint_intel_record("ip") for _ in range(10)]
        for ioc in iocs:
            ioc["lifecycle"] = "active"
        stale_iocs = [generate_stale_ioc(days_old=200) for _ in range(5)]
        for ioc in stale_iocs:
            ioc["lifecycle"] = "active"
        all_iocs = iocs + stale_iocs
        results = engine.evaluate(all_iocs)
        assert len(results) == len(all_iocs)
        deprecated_count = sum(1 for r in results if r["lifecycle"] == "deprecated")
        assert deprecated_count >= 5

    def test_deprecate_method(self, engine):
        ioc = generate_osint_intel_record("ip")
        deprecated = engine.deprecate(ioc, reason="age threshold exceeded")
        assert deprecated["lifecycle"] == "deprecated"

    def test_empty_list_returns_empty(self, engine):
        result = engine.evaluate([])
        assert result == []
