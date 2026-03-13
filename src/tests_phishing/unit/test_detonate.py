"""Unit tests for detonate_urls_attachments node (FR-04)."""

from unittest.mock import patch

from phishing_defense_agent.nodes.extract import extract_email_features
from phishing_defense_agent.nodes.detonate import detonate_urls_attachments
from tests_phishing.mocks.generators import (
    generate_clean_internal_email,
    generate_credential_harvest_email,
    generate_malware_delivery_email,
    generate_url_phishing_email,
    generate_clean_with_attachment,
)


def _state_with_features(email: dict) -> dict:
    return extract_email_features({"raw_emails": [email]})


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


class TestDetonateUrlsAttachments:
    @patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url)
    @patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment)
    def test_clean_email_no_detonation(self, mock_att, mock_url):
        state = _state_with_features(generate_clean_internal_email())
        result = detonate_urls_attachments(state)
        assert len(result["sandbox_results"]) == 1
        assert result["sandbox_results"][0]["overall_verdict"] == "clean"

    @patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url)
    @patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment)
    def test_phishing_url_detected(self, mock_att, mock_url):
        state = _state_with_features(generate_credential_harvest_email())
        result = detonate_urls_attachments(state)
        sandbox = result["sandbox_results"][0]
        malicious_urls = [r for r in sandbox["url_results"] if r["sandbox_verdict"] == "malicious"]
        assert len(malicious_urls) >= 1

    @patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url)
    @patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment)
    def test_malware_attachment_detected(self, mock_att, mock_url):
        state = _state_with_features(generate_malware_delivery_email())
        result = detonate_urls_attachments(state)
        sandbox = result["sandbox_results"][0]
        assert sandbox["overall_verdict"] == "malicious"

    @patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url)
    @patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment)
    def test_url_shortener_suspicious(self, mock_att, mock_url):
        state = _state_with_features(generate_url_phishing_email())
        result = detonate_urls_attachments(state)
        sandbox = result["sandbox_results"][0]
        verdicts = {r["sandbox_verdict"] for r in sandbox["url_results"]}
        assert "suspicious" in verdicts or "malicious" in verdicts

    @patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url)
    @patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment)
    def test_overall_verdict_malicious_wins(self, mock_att, mock_url):
        state = _state_with_features(generate_url_phishing_email())
        result = detonate_urls_attachments(state)
        sandbox = result["sandbox_results"][0]
        assert sandbox["overall_verdict"] in ("malicious", "suspicious")

    @patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url)
    @patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment)
    def test_message_id_preserved(self, mock_att, mock_url):
        state = _state_with_features(generate_credential_harvest_email())
        msg_id = state["email_features"][0]["message_id"]
        result = detonate_urls_attachments(state)
        assert result["sandbox_results"][0]["message_id"] == msg_id

    @patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url)
    @patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment)
    def test_handles_empty_features(self, mock_att, mock_url):
        result = detonate_urls_attachments({"email_features": []})
        assert result["sandbox_results"] == []

    @patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url)
    @patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment)
    def test_counts_scanned_items(self, mock_att, mock_url):
        state = _state_with_features(generate_url_phishing_email())
        result = detonate_urls_attachments(state)
        sandbox = result["sandbox_results"][0]
        assert sandbox["urls_scanned"] >= 1

    @patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url)
    @patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment)
    def test_clean_attachment_safe(self, mock_att, mock_url):
        state = _state_with_features(generate_clean_with_attachment())
        result = detonate_urls_attachments(state)
        sandbox = result["sandbox_results"][0]
        assert sandbox["overall_verdict"] == "clean"
