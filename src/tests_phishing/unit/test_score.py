"""Unit tests for score_phishing_risk node (FR-05)."""

from __future__ import annotations

import pytest

from phishing_defense_agent.nodes.extract import extract_email_features
from phishing_defense_agent.nodes.auth import validate_sender_auth
from phishing_defense_agent.nodes.language import analyze_language_intent
from phishing_defense_agent.nodes.score import (
    _auth_risk_score,
    _content_risk_score,
    _url_risk_score,
    _attachment_risk_score,
    _threat_intel_score,
    _determine_verdict,
    score_phishing_risk,
)
from phishing_defense_agent.config import get_settings
from tests_phishing.mocks.generators import (
    generate_clean_internal_email,
    generate_credential_harvest_email,
    generate_malware_delivery_email,
    generate_url_phishing_email,
    generate_bec_email,
)


def _pipeline_state(email: dict) -> dict:
    """Run extract → auth → language to build a partial state."""
    s = extract_email_features({"raw_emails": [email]})
    s.update(validate_sender_auth(s))
    s.update(analyze_language_intent(s))
    # Add empty sandbox results
    mid = s["email_features"][0]["message_id"]
    s["sandbox_results"] = [
        {
            "message_id": mid,
            "url_results": [],
            "attachment_results": [],
            "overall_verdict": "clean",
            "urls_scanned": 0,
            "attachments_scanned": 0,
        }
    ]
    return s


class TestComponentScores:
    def test_auth_risk_high_for_low_reputation(self):
        assert _auth_risk_score({"sender_reputation_score": 10.0}) == 90.0

    def test_auth_risk_low_for_high_reputation(self):
        assert _auth_risk_score({"sender_reputation_score": 95.0}) == 5.0

    def test_auth_risk_defaults_to_50(self):
        assert _auth_risk_score({}) == 50.0

    def test_content_risk_empty_signals(self):
        assert _content_risk_score([]) == 0.0

    def test_content_risk_single_signal(self):
        score = _content_risk_score([{"confidence": 0.9}])
        assert score > 50.0

    def test_content_risk_multiple_signals_bonus(self):
        one = _content_risk_score([{"confidence": 0.5}])
        two = _content_risk_score([{"confidence": 0.5}, {"confidence": 0.5}])
        assert two > one

    def test_url_risk_malicious(self):
        sandbox = {"url_results": [{"sandbox_verdict": "malicious"}]}
        assert _url_risk_score(sandbox) == 100.0

    def test_url_risk_clean(self):
        sandbox = {"url_results": [{"sandbox_verdict": "clean"}]}
        assert _url_risk_score(sandbox) == 0.0

    def test_url_risk_empty(self):
        assert _url_risk_score({}) == 0.0

    def test_attachment_risk_malicious(self):
        sandbox = {"attachment_results": [{"sandbox_verdict": "malicious"}]}
        assert _attachment_risk_score(sandbox) == 100.0

    def test_attachment_risk_clean(self):
        sandbox = {"attachment_results": [{"sandbox_verdict": "clean"}]}
        assert _attachment_risk_score(sandbox) == 0.0

    def test_threat_intel_lookalike(self):
        score = _threat_intel_score({"is_lookalike_domain": True}, {})
        assert score >= 40.0

    def test_threat_intel_new_domain(self):
        score = _threat_intel_score({"domain_age_days": 5}, {})
        assert score >= 20.0


class TestDetermineVerdict:
    def test_block_threshold(self):
        settings = get_settings()
        v, a = _determine_verdict(settings.risk_threshold_block, settings)
        assert a == "block"

    def test_quarantine_threshold(self):
        settings = get_settings()
        v, a = _determine_verdict(settings.risk_threshold_quarantine, settings)
        assert a == "quarantine"

    def test_warn_threshold(self):
        settings = get_settings()
        v, a = _determine_verdict(settings.risk_threshold_warn, settings)
        assert a == "warn"

    def test_allow_below_warn(self):
        settings = get_settings()
        v, a = _determine_verdict(10.0, settings)
        assert a == "allow"
        assert v == "clean"


class TestScorePhishingRisk:
    def test_clean_email_low_score(self):
        state = _pipeline_state(generate_clean_internal_email())
        result = score_phishing_risk(state)
        scores = result["risk_scores"]
        assert len(scores) == 1
        assert scores[0]["action"] == "allow"

    def test_credential_harvest_high_score(self):
        state = _pipeline_state(generate_credential_harvest_email())
        result = score_phishing_risk(state)
        assert result["risk_scores"][0]["risk_score"] > 0

    def test_score_has_components(self):
        state = _pipeline_state(generate_clean_internal_email())
        result = score_phishing_risk(state)
        comp = result["risk_scores"][0]["components"]
        assert "sender_auth" in comp
        assert "content_analysis" in comp
        assert "url_reputation" in comp
        assert "attachment_risk" in comp
        assert "threat_intel" in comp

    def test_score_has_explanation(self):
        state = _pipeline_state(generate_credential_harvest_email())
        result = score_phishing_risk(state)
        assert "Risk score" in result["risk_scores"][0]["explanation"]

    def test_message_id_preserved(self):
        state = _pipeline_state(generate_clean_internal_email())
        mid = state["email_features"][0]["message_id"]
        result = score_phishing_risk(state)
        assert result["risk_scores"][0]["message_id"] == mid

    def test_empty_features(self):
        result = score_phishing_risk({
            "email_features": [],
            "auth_results": [],
            "content_signals": [],
            "sandbox_results": [],
        })
        assert result["risk_scores"] == []

    def test_confidence_increases_with_signals(self):
        state = _pipeline_state(generate_credential_harvest_email())
        result = score_phishing_risk(state)
        assert result["risk_scores"][0]["confidence"] >= 0.5
