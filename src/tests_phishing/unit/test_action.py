"""Unit tests for apply_mail_action node (FR-05/06/07/09)."""

from __future__ import annotations

from phishing_defense_agent.nodes.action import apply_mail_action
from tests_phishing.mocks.generators import (
    generate_clean_internal_email,
    generate_credential_harvest_email,
    generate_malware_delivery_email,
)


def _make_scored(message_id: str, risk_score: float, verdict: str, action: str) -> dict:
    return {
        "message_id": message_id,
        "risk_score": risk_score,
        "verdict": verdict,
        "action": action,
        "confidence": 0.85,
        "explanation": f"Risk score: {risk_score}",
        "components": {
            "sender_auth": 20.0,
            "content_analysis": 30.0,
            "url_reputation": 10.0,
            "attachment_risk": 0.0,
            "threat_intel": 5.0,
        },
    }


def _make_feature(message_id: str, **overrides) -> dict:
    feat = {
        "message_id": message_id,
        "subject": "Test Subject",
        "sender_address": "attacker@evil.com",
        "sender_domain": "evil.com",
        "recipient_addresses": ["user@company.com"],
        "urls": ["https://evil-phish.com/login"],
        "attachment_hashes": ["abc123"],
    }
    feat.update(overrides)
    return feat


class TestApplyMailAction:
    def test_block_action(self):
        mid = "msg-block-001"
        state = {
            "risk_scores": [_make_scored(mid, 90.0, "malicious", "block")],
            "email_features": [_make_feature(mid)],
        }
        result = apply_mail_action(state)
        verdict = result["verdicts"][0]
        assert verdict["action"] == "block"
        assert verdict["quarantine_status"] == "blocked"

    def test_quarantine_action(self):
        mid = "msg-quar-001"
        state = {
            "risk_scores": [_make_scored(mid, 70.0, "malicious", "quarantine")],
            "email_features": [_make_feature(mid)],
        }
        result = apply_mail_action(state)
        verdict = result["verdicts"][0]
        assert verdict["action"] == "quarantine"
        assert verdict["quarantine_status"] == "quarantined"
        assert verdict["quarantine_id"].startswith("quar-")

    def test_warn_action(self):
        mid = "msg-warn-001"
        state = {
            "risk_scores": [_make_scored(mid, 50.0, "suspicious", "warn")],
            "email_features": [_make_feature(mid)],
        }
        result = apply_mail_action(state)
        verdict = result["verdicts"][0]
        assert verdict["action"] == "warn"
        assert verdict["warning_applied"] is True

    def test_allow_action(self):
        mid = "msg-allow-001"
        state = {
            "risk_scores": [_make_scored(mid, 10.0, "clean", "allow")],
            "email_features": [_make_feature(mid)],
        }
        result = apply_mail_action(state)
        verdict = result["verdicts"][0]
        assert verdict["action"] == "allow"
        assert verdict["quarantine_status"] == "allowed"

    def test_ioc_extraction_on_block(self):
        mid = "msg-ioc-001"
        state = {
            "risk_scores": [_make_scored(mid, 90.0, "malicious", "block")],
            "email_features": [_make_feature(mid)],
        }
        result = apply_mail_action(state)
        iocs = result["extracted_iocs"]
        ioc_types = {ioc["ioc_type"] for ioc in iocs}
        assert "url" in ioc_types
        assert "domain" in ioc_types
        assert "file_hash" in ioc_types

    def test_no_iocs_on_allow(self):
        mid = "msg-noic-001"
        state = {
            "risk_scores": [_make_scored(mid, 10.0, "clean", "allow")],
            "email_features": [_make_feature(mid)],
        }
        result = apply_mail_action(state)
        assert result["extracted_iocs"] == []

    def test_no_iocs_on_warn(self):
        mid = "msg-wioc-001"
        state = {
            "risk_scores": [_make_scored(mid, 50.0, "suspicious", "warn")],
            "email_features": [_make_feature(mid)],
        }
        result = apply_mail_action(state)
        assert result["extracted_iocs"] == []

    def test_processed_at_present(self):
        mid = "msg-ts-001"
        state = {
            "risk_scores": [_make_scored(mid, 10.0, "clean", "allow")],
            "email_features": [_make_feature(mid)],
        }
        result = apply_mail_action(state)
        assert "processed_at" in result["verdicts"][0]

    def test_empty_input(self):
        result = apply_mail_action({"risk_scores": [], "email_features": []})
        assert result["verdicts"] == []
        assert result["extracted_iocs"] == []

    def test_multiple_emails(self):
        state = {
            "risk_scores": [
                _make_scored("m1", 90.0, "malicious", "block"),
                _make_scored("m2", 10.0, "clean", "allow"),
            ],
            "email_features": [
                _make_feature("m1"),
                _make_feature("m2", urls=[], attachment_hashes=[]),
            ],
        }
        result = apply_mail_action(state)
        assert len(result["verdicts"]) == 2
        assert result["verdicts"][0]["action"] == "block"
        assert result["verdicts"][1]["action"] == "allow"

    def test_ioc_tags_contain_verdict_and_action(self):
        mid = "msg-tag-001"
        state = {
            "risk_scores": [_make_scored(mid, 70.0, "malicious", "quarantine")],
            "email_features": [_make_feature(mid)],
        }
        result = apply_mail_action(state)
        for ioc in result["extracted_iocs"]:
            assert "malicious" in ioc["tags"]
            assert "quarantine" in ioc["tags"]
