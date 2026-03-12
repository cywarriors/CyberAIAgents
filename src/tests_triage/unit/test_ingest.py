"""Unit tests for IngestAlertNode."""

from incident_triage_agent.nodes.ingest import ingest_alert
from tests_triage.mocks.generators import generate_brute_force_alert, generate_benign_auth_alert


class TestIngestAlert:
    def test_assigns_batch_id(self):
        alert = generate_brute_force_alert()
        result = ingest_alert({"raw_alerts": [alert]})
        assert result["triage_batch_id"]
        assert result["triage_batch_id"].startswith("triage-")

    def test_preserves_alerts(self):
        alerts = [generate_brute_force_alert(), generate_benign_auth_alert()]
        result = ingest_alert({"raw_alerts": alerts})
        assert len(result["raw_alerts"]) == 2

    def test_stamps_ingested_at(self):
        alert = generate_brute_force_alert()
        result = ingest_alert({"raw_alerts": [alert]})
        assert result["raw_alerts"][0].get("_ingested_at")

    def test_stamps_batch_id_on_each_alert(self):
        alerts = [generate_brute_force_alert(), generate_benign_auth_alert()]
        result = ingest_alert({"raw_alerts": alerts})
        for a in result["raw_alerts"]:
            assert a["_batch_id"] == result["triage_batch_id"]

    def test_handles_empty_alerts(self):
        result = ingest_alert({"raw_alerts": []})
        assert result["triage_batch_id"]
        assert result["raw_alerts"] == []

    def test_preserves_existing_batch_id(self):
        result = ingest_alert({"triage_batch_id": "custom-id", "raw_alerts": [generate_brute_force_alert()]})
        assert result["triage_batch_id"] == "custom-id"

    def test_assigns_alert_id_if_missing(self):
        alert = {"severity": "High", "description": "test"}
        result = ingest_alert({"raw_alerts": [alert]})
        assert result["raw_alerts"][0]["alert_id"].startswith("alert-")
