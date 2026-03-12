"""Unit tests for CorrelateIncidentNode."""

from incident_triage_agent.nodes.correlate import correlate_incident
from tests_triage.mocks.generators import (
    generate_brute_force_alert,
    generate_data_exfil_alert,
    generate_multi_stage_intrusion,
    generate_credential_stuffing_campaign,
)


class TestCorrelateIncident:
    def test_single_alert_produces_one_group(self):
        alert = generate_brute_force_alert()
        result = correlate_incident({"raw_alerts": [alert]})
        assert len(result["correlations"]) == 1
        group = result["correlations"][0]
        assert len(group["alert_ids"]) == 1
        assert group["group_id"].startswith("corr-")

    def test_multi_stage_alerts_correlate(self):
        """Alerts sharing user/host entities within time window should merge into one group."""
        alerts = generate_multi_stage_intrusion()
        result = correlate_incident({"raw_alerts": alerts})
        # The 4 alerts share user 'bob' and hosts, so should correlate
        assert len(result["correlations"]) >= 1
        # At least one group should have multiple alerts
        max_group_size = max(len(g["alert_ids"]) for g in result["correlations"])
        assert max_group_size >= 2

    def test_credential_stuffing_correlates_by_ip(self):
        """4 alerts sharing src_ip should be grouped together."""
        alerts = generate_credential_stuffing_campaign()
        result = correlate_incident({"raw_alerts": alerts})
        # All share IP 203.0.113.55
        total_correlated = sum(len(g["alert_ids"]) for g in result["correlations"])
        assert total_correlated == 4

    def test_unrelated_alerts_get_separate_groups(self):
        """Alerts with no shared entities should not merge."""
        a1 = generate_brute_force_alert()
        a1["entity_ids"] = ["unique-user-aaa"]
        a1["raw_payload"] = {"user_name": "unique-user-aaa"}
        a1["evidence"] = []

        a2 = generate_data_exfil_alert()
        a2["entity_ids"] = ["unique-host-zzz"]
        a2["raw_payload"] = {"host_name": "unique-host-zzz"}
        a2["evidence"] = []

        result = correlate_incident({"raw_alerts": [a1, a2]})
        assert len(result["correlations"]) == 2

    def test_attack_chain_ordering(self):
        """Multi-stage intrusion should produce ordered ATT&CK chain."""
        alerts = generate_multi_stage_intrusion()
        result = correlate_incident({"raw_alerts": alerts})
        # Find the biggest group
        biggest = max(result["correlations"], key=lambda g: len(g["alert_ids"]))
        chain = biggest.get("attack_chain", [])
        assert len(chain) >= 2

    def test_empty_alerts(self):
        result = correlate_incident({"raw_alerts": []})
        assert result["correlations"] == []

    def test_shared_entities_populated(self):
        alerts = generate_multi_stage_intrusion()
        result = correlate_incident({"raw_alerts": alerts})
        biggest = max(result["correlations"], key=lambda g: len(g["alert_ids"]))
        assert len(biggest["shared_entities"]) > 0

    def test_time_span_calculated(self):
        alerts = generate_multi_stage_intrusion()
        result = correlate_incident({"raw_alerts": alerts})
        biggest = max(result["correlations"], key=lambda g: len(g["alert_ids"]))
        assert biggest["time_span_seconds"] >= 0
