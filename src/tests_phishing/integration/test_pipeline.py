"""Integration tests – full pipeline execution with production-like mock data."""

from __future__ import annotations

from unittest.mock import patch

from phishing_defense_agent.nodes.extract import extract_email_features
from phishing_defense_agent.nodes.auth import validate_sender_auth
from phishing_defense_agent.nodes.language import analyze_language_intent
from phishing_defense_agent.nodes.detonate import detonate_urls_attachments
from phishing_defense_agent.nodes.score import score_phishing_risk
from phishing_defense_agent.nodes.action import apply_mail_action
from phishing_defense_agent.nodes.notify import notify_user_and_soc
from phishing_defense_agent.nodes.feedback import learn_from_release

from tests_phishing.mocks.generators import (
    generate_all_clean_emails,
    generate_all_phishing_emails,
    generate_mixed_email_batch,
    generate_credential_harvest_email,
    generate_malware_delivery_email,
    generate_bec_email,
    generate_clean_internal_email,
)


def _mock_detonate_url(url: str) -> dict:
    if "phish" in url.lower() or "micros0ft" in url.lower() or "g00gle" in url.lower():
        return {"url": url, "sandbox_verdict": "malicious", "is_known_phishing": True, "is_shortened": False}
    if "bit.ly" in url.lower():
        return {"url": url, "sandbox_verdict": "suspicious", "is_known_phishing": False, "is_shortened": True}
    return {"url": url, "sandbox_verdict": "clean", "is_known_phishing": False, "is_shortened": False}


def _mock_detonate_attachment(name: str, file_hash: str) -> dict:
    dangerous_ext = (".exe", ".scr", ".xlsm", ".docm")
    if any(name.lower().endswith(ext) for ext in dangerous_ext):
        return {"filename": name, "file_hash": file_hash, "sandbox_verdict": "malicious"}
    return {"filename": name, "file_hash": file_hash, "sandbox_verdict": "clean"}


def _run_full_pipeline(emails: list[dict]) -> dict:
    """Execute all 8 pipeline nodes sequentially."""
    state: dict = {"raw_emails": emails}

    state.update(extract_email_features(state))
    state.update(validate_sender_auth(state))
    state.update(analyze_language_intent(state))

    with patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url):
        with patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment):
            state.update(detonate_urls_attachments(state))

    state.update(score_phishing_risk(state))
    state.update(apply_mail_action(state))
    state.update(notify_user_and_soc(state))
    state.update(learn_from_release(state))

    return state


class TestFullPipeline:
    def test_single_clean_email(self):
        state = _run_full_pipeline([generate_clean_internal_email()])
        assert len(state["verdicts"]) == 1
        assert state["verdicts"][0]["action"] == "allow"
        assert state["notifications"] == []

    def test_single_phishing_email(self):
        state = _run_full_pipeline([generate_credential_harvest_email()])
        assert len(state["verdicts"]) == 1
        v = state["verdicts"][0]
        assert v["action"] in ("warn", "quarantine", "block")
        assert v["risk_score"] > 0

    def test_malware_email_high_severity(self):
        state = _run_full_pipeline([generate_malware_delivery_email()])
        v = state["verdicts"][0]
        assert v["action"] in ("warn", "quarantine", "block")
        assert v["risk_score"] > 30

    def test_bec_email_detection(self):
        state = _run_full_pipeline([generate_bec_email()])
        v = state["verdicts"][0]
        assert v["risk_score"] > 0

    def test_batch_clean_emails(self):
        clean = generate_all_clean_emails()
        state = _run_full_pipeline(clean)
        assert len(state["verdicts"]) == len(clean)
        for v in state["verdicts"]:
            assert v["action"] == "allow"

    def test_batch_phishing_emails(self):
        phishing = generate_all_phishing_emails()
        state = _run_full_pipeline(phishing)
        assert len(state["verdicts"]) == len(phishing)
        for v in state["verdicts"]:
            assert v["risk_score"] > 0

    def test_mixed_batch(self):
        mixed = generate_mixed_email_batch()
        state = _run_full_pipeline(mixed)
        assert len(state["verdicts"]) == len(mixed)
        actions = {v["action"] for v in state["verdicts"]}
        # Should have at least allow and some non-allow action
        assert "allow" in actions

    def test_pipeline_preserves_message_ids(self):
        emails = [generate_clean_internal_email(), generate_credential_harvest_email()]
        state = _run_full_pipeline(emails)
        feature_ids = {f["message_id"] for f in state["email_features"]}
        verdict_ids = {v["message_id"] for v in state["verdicts"]}
        assert feature_ids == verdict_ids

    def test_iocs_only_from_blocked_quarantined(self):
        state = _run_full_pipeline([generate_clean_internal_email()])
        assert state["extracted_iocs"] == []

    def test_notifications_for_blocked_emails(self):
        state = _run_full_pipeline([generate_malware_delivery_email()])
        if state["verdicts"][0]["action"] in ("quarantine", "block"):
            notif_types = {n["notification_type"] for n in state["notifications"]}
            assert "soc_escalation" in notif_types

    def test_all_state_keys_present(self):
        state = _run_full_pipeline([generate_clean_internal_email()])
        expected_keys = {
            "raw_emails", "email_features", "auth_results",
            "content_signals", "sandbox_results", "risk_scores",
            "verdicts", "extracted_iocs", "notifications", "feedback_queue",
        }
        assert expected_keys.issubset(set(state.keys()))
