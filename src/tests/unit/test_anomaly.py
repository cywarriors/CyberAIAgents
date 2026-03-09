"""Unit tests for BehaviorAnomalyNode."""

import pytest
from threat_detection_agent.nodes.normalize import normalize_schema
from threat_detection_agent.nodes.anomaly import behavior_anomaly
from tests.mocks.generators import (
    generate_benign_auth_event,
    generate_brute_force_event,
    generate_data_exfil_event,
    generate_dns_tunnelling_event,
)


def _normalize_and_anomaly(raw_event):
    norm = normalize_schema({"raw_events": [raw_event]})
    return behavior_anomaly({"normalized_events": norm["normalized_events"]})


class TestBehaviorAnomaly:
    def test_benign_auth_no_anomaly(self):
        result = _normalize_and_anomaly(generate_benign_auth_event())
        assert len(result["anomalies"]) == 0

    def test_brute_force_triggers_anomaly(self):
        result = _normalize_and_anomaly(generate_brute_force_event())
        assert len(result["anomalies"]) >= 1
        assert result["anomalies"][0]["anomaly_type"] == "excessive_failed_logins"

    def test_data_exfil_triggers_anomaly(self):
        result = _normalize_and_anomaly(generate_data_exfil_event())
        assert any(a["anomaly_type"] == "high_outbound_bytes" for a in result["anomalies"])

    def test_dns_tunnelling_triggers_anomaly(self):
        result = _normalize_and_anomaly(generate_dns_tunnelling_event())
        assert any(a["anomaly_type"] == "dns_tunnelling_suspect" for a in result["anomalies"])

    def test_anomaly_scores_in_range(self):
        result = _normalize_and_anomaly(generate_brute_force_event())
        for a in result["anomalies"]:
            assert 0.0 <= a["anomaly_score"] <= 1.0
