"""Unit tests for GenerateSummaryNode."""

from incident_triage_agent.nodes.summarize import generate_summary
from tests_triage.mocks.generators import (
    generate_brute_force_alert,
    generate_data_exfil_alert,
    generate_insider_threat_alert,
    generate_malware_execution_alert,
    generate_phishing_alert,
    generate_ransomware_alert,
)


def _make_state(alerts, entity_context=None, correlations=None, priority_scores=None):
    return {
        "raw_alerts": alerts,
        "entity_context": entity_context or [],
        "correlations": correlations or [],
        "priority_scores": priority_scores or [],
    }


class TestGenerateSummary:
    def test_classifies_brute_force(self):
        alert = generate_brute_force_alert()
        result = generate_summary(_make_state([alert]))
        classifications = result["classifications"]
        assert len(classifications) == 1
        assert classifications[0]["classification"] == "credential_abuse"

    def test_classifies_data_exfil(self):
        alert = generate_data_exfil_alert()
        result = generate_summary(_make_state([alert]))
        assert result["classifications"][0]["classification"] == "data_exfiltration"

    def test_classifies_malware(self):
        alert = generate_malware_execution_alert()
        result = generate_summary(_make_state([alert]))
        assert result["classifications"][0]["classification"] == "malware"

    def test_classifies_phishing(self):
        alert = generate_phishing_alert()
        result = generate_summary(_make_state([alert]))
        assert result["classifications"][0]["classification"] == "phishing"

    def test_classifies_ransomware(self):
        alert = generate_ransomware_alert()
        result = generate_summary(_make_state([alert]))
        assert result["classifications"][0]["classification"] == "ransomware"

    def test_insider_threat_detection(self):
        alert = generate_insider_threat_alert()
        entity_context = [
            {"entity_type": "user", "entity_id": "charlie", "is_privileged": True},
        ]
        result = generate_summary(_make_state([alert], entity_context))
        # Insider threat signals in evidence + privileged user
        assert result["classifications"][0]["classification"] == "insider_threat"

    def test_summary_text_contains_sections(self):
        alert = generate_data_exfil_alert()
        priority_scores = [{"priority": "P1", "confidence": 92, "components": {
            "asset_criticality": 80, "threat_intel": 50, "user_risk": 30,
            "alert_severity": 100, "historical_accuracy": 50,
        }}]
        result = generate_summary(_make_state([alert], priority_scores=priority_scores))
        text = result["triage_summaries"][0]["text"]
        assert "INCIDENT TRIAGE SUMMARY" in text
        assert "KEY FINDINGS" in text
        assert "AFFECTED ENTITIES" in text

    def test_empty_alerts(self):
        result = generate_summary(_make_state([]))
        assert result["triage_summaries"] == []
        assert result["classifications"] == []

    def test_unknown_classification_for_no_techniques(self):
        alert = {"alert_id": "x", "severity": "Low", "description": "noise",
                 "mitre_technique_ids": [], "mitre_tactics": [], "evidence": []}
        result = generate_summary(_make_state([alert]))
        assert result["classifications"][0]["classification"] == "unknown"
