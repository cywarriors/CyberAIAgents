"""Unit tests for EnrichEntityNode."""

from incident_triage_agent.nodes.enrich import enrich_entity
from tests_triage.mocks.generators import (
    generate_brute_force_alert,
    generate_insider_threat_alert,
    generate_data_exfil_alert,
)


class TestEnrichEntity:
    def test_enriches_known_user(self):
        alert = generate_insider_threat_alert()
        result = enrich_entity({"raw_alerts": [alert]})
        profiles = result["entity_context"]
        assert len(profiles) > 0
        user_profiles = [p for p in profiles if p["entity_type"] == "user"]
        assert any(p.get("is_privileged") for p in user_profiles)

    def test_enriches_known_host(self):
        alert = generate_data_exfil_alert()
        # Force a known host entity
        alert["entity_ids"] = ["srv-db-01"]
        result = enrich_entity({"raw_alerts": [alert]})
        profiles = result["entity_context"]
        host_profiles = [p for p in profiles if p["entity_type"] == "host"]
        assert any(p.get("asset_criticality") == "critical" for p in host_profiles)

    def test_enriches_ip_with_geo(self):
        alert = generate_brute_force_alert()
        alert["entity_ids"] = ["203.0.113.55"]
        result = enrich_entity({"raw_alerts": [alert]})
        profiles = result["entity_context"]
        ip_profiles = [p for p in profiles if p["entity_type"] == "ip"]
        assert any(p.get("geo_country") for p in ip_profiles)

    def test_partial_enrichment_for_unknown(self):
        alert = {"entity_ids": ["unknown-entity-xyz"], "raw_payload": {}, "evidence": []}
        result = enrich_entity({"raw_alerts": [alert]})
        profiles = result["entity_context"]
        assert len(profiles) == 1
        # Unknown user should still get a profile

    def test_empty_alerts(self):
        result = enrich_entity({"raw_alerts": []})
        assert result["entity_context"] == []

    def test_deduplicates_entities(self):
        """Same entity across multiple alerts should appear once."""
        a1 = generate_brute_force_alert()
        a2 = generate_brute_force_alert()
        # Force same entities
        a1["entity_ids"] = ["alice", "ws-001"]
        a2["entity_ids"] = ["alice", "ws-001"]
        a1["raw_payload"] = {}
        a2["raw_payload"] = {}
        a1["evidence"] = []
        a2["evidence"] = []
        result = enrich_entity({"raw_alerts": [a1, a2]})
        entity_ids = [p["entity_id"] for p in result["entity_context"]]
        assert len(entity_ids) == len(set(entity_ids))

    def test_enrichment_quality_field_present(self):
        alert = generate_insider_threat_alert()
        result = enrich_entity({"raw_alerts": [alert]})
        for profile in result["entity_context"]:
            assert "enrichment_quality" in profile
