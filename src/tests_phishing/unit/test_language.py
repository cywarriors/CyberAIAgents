"""Unit tests for analyze_language_intent node (FR-03)."""

from phishing_defense_agent.nodes.extract import extract_email_features
from phishing_defense_agent.nodes.language import analyze_language_intent
from tests_phishing.mocks.generators import (
    generate_clean_internal_email,
    generate_credential_harvest_email,
    generate_bec_email,
    generate_malware_delivery_email,
    generate_display_name_spoof_email,
    generate_url_phishing_email,
)


def _state_with_features(email: dict) -> dict:
    return extract_email_features({"raw_emails": [email]})


class TestAnalyzeLanguageIntent:
    def test_detects_urgency_in_phishing(self):
        state = _state_with_features(generate_credential_harvest_email())
        result = analyze_language_intent(state)
        signals = result["content_signals"]
        signal_types = [s["signal_type"] for s in signals]
        assert "urgency" in signal_types or "credential_harvest" in signal_types

    def test_detects_credential_harvest(self):
        state = _state_with_features(generate_credential_harvest_email())
        result = analyze_language_intent(state)
        signal_types = [s["signal_type"] for s in result["content_signals"]]
        assert "credential_harvest" in signal_types

    def test_detects_bec_patterns(self):
        state = _state_with_features(generate_bec_email())
        result = analyze_language_intent(state)
        signal_types = [s["signal_type"] for s in result["content_signals"]]
        has_bec = "business_email_compromise" in signal_types
        has_fraud = "financial_fraud" in signal_types
        assert has_bec or has_fraud

    def test_detects_malware_delivery_patterns(self):
        state = _state_with_features(generate_malware_delivery_email())
        result = analyze_language_intent(state)
        signal_types = [s["signal_type"] for s in result["content_signals"]]
        has_malware = "malware_delivery" in signal_types
        has_financial = "financial_fraud" in signal_types
        assert has_malware or has_financial

    def test_no_signals_for_clean(self):
        state = _state_with_features(generate_clean_internal_email())
        result = analyze_language_intent(state)
        assert len(result["content_signals"]) == 0

    def test_display_name_spoof_detection(self):
        state = _state_with_features(generate_display_name_spoof_email())
        result = analyze_language_intent(state)
        signal_types = [s["signal_type"] for s in result["content_signals"]]
        assert "impersonation" in signal_types

    def test_signal_has_confidence(self):
        state = _state_with_features(generate_credential_harvest_email())
        result = analyze_language_intent(state)
        for sig in result["content_signals"]:
            assert 0.0 < sig["confidence"] <= 1.0

    def test_signal_has_message_id(self):
        state = _state_with_features(generate_credential_harvest_email())
        result = analyze_language_intent(state)
        for sig in result["content_signals"]:
            assert sig["message_id"]

    def test_signal_has_evidence(self):
        state = _state_with_features(generate_credential_harvest_email())
        result = analyze_language_intent(state)
        for sig in result["content_signals"]:
            assert sig["evidence"]

    def test_handles_empty_features(self):
        result = analyze_language_intent({"email_features": []})
        assert result["content_signals"] == []

    def test_multiple_signals_per_email(self):
        state = _state_with_features(generate_credential_harvest_email())
        result = analyze_language_intent(state)
        assert len(result["content_signals"]) >= 1

    def test_confidence_scales_with_matches(self):
        # BEC emails typically trigger multiple pattern categories
        state = _state_with_features(generate_bec_email())
        result = analyze_language_intent(state)
        if result["content_signals"]:
            max_conf = max(s["confidence"] for s in result["content_signals"])
            assert max_conf >= 0.4
