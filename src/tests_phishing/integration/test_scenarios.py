"""Integration tests using pre-built phishing scenarios with expected outcomes."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from phishing_defense_agent.nodes.extract import extract_email_features
from phishing_defense_agent.nodes.auth import validate_sender_auth
from phishing_defense_agent.nodes.language import analyze_language_intent
from phishing_defense_agent.nodes.detonate import detonate_urls_attachments
from phishing_defense_agent.nodes.score import score_phishing_risk
from phishing_defense_agent.nodes.action import apply_mail_action

from tests_phishing.mocks.scenarios import SCENARIOS, SCENARIO_BY_NAME


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


def _run_pipeline_for_scenario(emails: list[dict]) -> dict:
    state: dict = {"raw_emails": emails}
    state.update(extract_email_features(state))
    state.update(validate_sender_auth(state))
    state.update(analyze_language_intent(state))

    with patch("phishing_defense_agent.nodes.detonate.detonate_url", side_effect=_mock_detonate_url):
        with patch("phishing_defense_agent.nodes.detonate.detonate_attachment", side_effect=_mock_detonate_attachment):
            state.update(detonate_urls_attachments(state))

    state.update(score_phishing_risk(state))
    state.update(apply_mail_action(state))
    return state


class TestPhishingScenarios:
    def test_credential_harvest(self):
        scenario = SCENARIO_BY_NAME["Credential Harvesting"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["risk_score"] >= scenario.expected_min_risk_score

    def test_bec_wire_fraud(self):
        scenario = SCENARIO_BY_NAME["Business Email Compromise"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["risk_score"] >= scenario.expected_min_risk_score

    def test_malware_delivery(self):
        scenario = SCENARIO_BY_NAME["Malware Delivery"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["action"] in ("warn", "quarantine", "block")
        assert v["risk_score"] > 30

    def test_lookalike_domain(self):
        scenario = SCENARIO_BY_NAME["Lookalike Domain"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["risk_score"] >= scenario.expected_min_risk_score

    def test_url_phishing(self):
        scenario = SCENARIO_BY_NAME["URL Phishing with Shorteners"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["risk_score"] >= scenario.expected_min_risk_score

    def test_spear_phishing_vip(self):
        scenario = SCENARIO_BY_NAME["VIP Spear Phishing"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["risk_score"] >= scenario.expected_min_risk_score

    def test_new_domain(self):
        scenario = SCENARIO_BY_NAME["New Domain Sender"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["risk_score"] >= scenario.expected_min_risk_score

    def test_display_name_spoof(self):
        scenario = SCENARIO_BY_NAME["Display Name Spoof"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["risk_score"] >= scenario.expected_min_risk_score

    def test_clean_internal(self):
        scenario = SCENARIO_BY_NAME["Clean Internal Email"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["action"] == scenario.expected_action

    def test_clean_external(self):
        scenario = SCENARIO_BY_NAME["Clean External Email"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["action"] == scenario.expected_action

    def test_clean_attachment(self):
        scenario = SCENARIO_BY_NAME["Clean with Attachment"]
        state = _run_pipeline_for_scenario(scenario.emails)
        v = state["verdicts"][0]
        assert v["action"] == scenario.expected_action
