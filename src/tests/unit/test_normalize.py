"""Unit tests for NormalizeSchemaNode."""

import pytest
from threat_detection_agent.nodes.normalize import normalize_schema
from tests.mocks.generators import generate_benign_auth_event, generate_data_exfil_event


class TestNormalizeSchema:
    def test_normalizes_auth_event(self):
        raw = generate_benign_auth_event()
        result = normalize_schema({"raw_events": [raw]})
        normalized = result["normalized_events"]
        assert len(normalized) == 1
        evt = normalized[0]
        assert evt["category"] == "authentication"
        assert evt["event_id"]
        assert evt["source"] == "siem"

    def test_normalizes_network_event(self):
        raw = generate_data_exfil_event()
        result = normalize_schema({"raw_events": [raw]})
        normalized = result["normalized_events"]
        assert len(normalized) == 1
        assert normalized[0]["source_type"] == "network"

    def test_handles_empty_batch(self):
        result = normalize_schema({"raw_events": []})
        assert result["normalized_events"] == []

    def test_preserves_raw_snippet(self):
        raw = generate_benign_auth_event()
        result = normalize_schema({"raw_events": [raw]})
        evt = result["normalized_events"][0]
        assert "raw_snippet" in evt
        assert evt["raw_snippet"].get("action") == "login_success"

    def test_infers_category_from_source_type(self):
        raw = {
            "source": "custom",
            "source_type": "firewall",
            "raw_payload": {"event_id": "e1", "action": "block", "source_type": "firewall"},
        }
        result = normalize_schema({"raw_events": [raw]})
        assert result["normalized_events"][0]["category"] == "firewall"
