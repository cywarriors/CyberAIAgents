"""Unit tests for notify_user_and_soc node (FR-06)."""

from __future__ import annotations

from phishing_defense_agent.nodes.notify import notify_user_and_soc


def _make_verdict(action: str, **overrides) -> dict:
    v = {
        "message_id": "msg-001",
        "risk_score": 75.0,
        "verdict": "malicious",
        "action": action,
        "sender_address": "attacker@evil.com",
        "recipient_addresses": ["user@company.com"],
        "subject": "Urgent: verify your account",
    }
    v.update(overrides)
    return v


class TestNotifyUserAndSoc:
    def test_warn_sends_user_warning(self):
        state = {"verdicts": [_make_verdict("warn")]}
        result = notify_user_and_soc(state)
        notifs = result["notifications"]
        assert len(notifs) == 1
        assert notifs[0]["notification_type"] == "user_warning"
        assert notifs[0]["channel"] == "email_banner"

    def test_quarantine_sends_two_notifications(self):
        state = {"verdicts": [_make_verdict("quarantine")]}
        result = notify_user_and_soc(state)
        types = {n["notification_type"] for n in result["notifications"]}
        assert "soc_escalation" in types
        assert "user_notification" in types

    def test_block_sends_soc_and_user(self):
        state = {"verdicts": [_make_verdict("block")]}
        result = notify_user_and_soc(state)
        assert len(result["notifications"]) == 2
        types = {n["notification_type"] for n in result["notifications"]}
        assert "soc_escalation" in types

    def test_allow_no_notifications(self):
        state = {"verdicts": [_make_verdict("allow")]}
        result = notify_user_and_soc(state)
        assert result["notifications"] == []

    def test_empty_verdicts(self):
        result = notify_user_and_soc({"verdicts": []})
        assert result["notifications"] == []

    def test_notification_has_message_id(self):
        state = {"verdicts": [_make_verdict("warn", message_id="unique-123")]}
        result = notify_user_and_soc(state)
        assert result["notifications"][0]["message_id"] == "unique-123"

    def test_soc_escalation_summary_contains_subject(self):
        state = {"verdicts": [_make_verdict("block", subject="Transfer $50k now")]}
        result = notify_user_and_soc(state)
        soc = [n for n in result["notifications"] if n["notification_type"] == "soc_escalation"][0]
        assert "Transfer $50k now" in soc["summary"]

    def test_warning_summary_contains_sender(self):
        state = {"verdicts": [_make_verdict("warn", sender_address="bad@evil.com")]}
        result = notify_user_and_soc(state)
        assert "bad@evil.com" in result["notifications"][0]["summary"]

    def test_sent_flag_true(self):
        state = {"verdicts": [_make_verdict("quarantine")]}
        result = notify_user_and_soc(state)
        for n in result["notifications"]:
            assert n["sent"] is True

    def test_multiple_verdicts(self):
        state = {
            "verdicts": [
                _make_verdict("warn", message_id="m1"),
                _make_verdict("block", message_id="m2"),
                _make_verdict("allow", message_id="m3"),
            ]
        }
        result = notify_user_and_soc(state)
        # warn=1, block=2, allow=0
        assert len(result["notifications"]) == 3
