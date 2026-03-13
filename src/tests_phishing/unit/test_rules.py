"""Unit tests for PhishingRuleEngine and baseline rules."""

from __future__ import annotations

from phishing_defense_agent.rules.engine import PhishingRuleEngine, BASELINE_RULES


def _ctx(auth=None, content_signals=None, sandbox=None) -> dict:
    return {
        "auth": auth or {},
        "content_signals": content_signals or [],
        "sandbox": sandbox or {},
    }


class TestBaselineRules:
    def test_auth_failure_spf(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(auth={"spf_status": "fail"}))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-AUTH-001" in ids

    def test_auth_failure_multiple(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(auth={
            "spf_status": "fail", "dkim_status": "fail", "dmarc_status": "fail"
        }))
        auth_match = [m for m in matches if m["rule_id"] == "PHISH-AUTH-001"][0]
        assert auth_match["severity"] == "high"
        assert auth_match["score_adjustment"] == 45.0

    def test_lookalike_domain(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(auth={"is_lookalike_domain": True}))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-DOMAIN-001" in ids

    def test_new_domain(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(auth={"domain_age_days": 5}))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-DOMAIN-002" in ids

    def test_old_domain_no_match(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(auth={"domain_age_days": 365}))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-DOMAIN-002" not in ids

    def test_credential_harvest(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(
            content_signals=[{"signal_type": "credential_harvest", "evidence": "sign in"}]
        ))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-CRED-001" in ids

    def test_malicious_attachment(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(
            sandbox={"attachment_results": [{"sandbox_verdict": "malicious", "filename": "evil.exe"}]}
        ))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-ATTACH-001" in ids

    def test_malicious_url(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(
            sandbox={"url_results": [{"sandbox_verdict": "malicious", "url": "https://evil.com"}]}
        ))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-URL-001" in ids

    def test_bec_rule(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(
            content_signals=[{"signal_type": "business_email_compromise", "evidence": "wire transfer"}]
        ))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-BEC-001" in ids

    def test_clean_email_no_matches(self):
        engine = PhishingRuleEngine()
        matches = engine.evaluate(_ctx(
            auth={"spf_status": "pass", "dkim_status": "pass", "dmarc_status": "pass"}
        ))
        assert matches == []


class TestPhishingRuleEngine:
    def test_baseline_rule_count(self):
        engine = PhishingRuleEngine()
        assert engine.rule_count == 7

    def test_add_custom_rule(self):
        engine = PhishingRuleEngine()
        engine.add_rule(lambda ctx: {"rule_id": "CUSTOM-001", "rule_name": "Custom"})
        assert engine.rule_count == 8

    def test_custom_rule_fires(self):
        engine = PhishingRuleEngine()
        engine.add_rule(lambda ctx: {
            "rule_id": "CUSTOM-001", "rule_name": "Custom",
            "severity": "low", "score_adjustment": 5.0
        })
        matches = engine.evaluate(_ctx())
        ids = [m["rule_id"] for m in matches]
        assert "CUSTOM-001" in ids

    def test_disable_rule(self):
        engine = PhishingRuleEngine()
        engine.disable_rule("PHISH-AUTH-001")
        matches = engine.evaluate(_ctx(auth={"spf_status": "fail"}))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-AUTH-001" not in ids

    def test_enable_rule(self):
        engine = PhishingRuleEngine()
        engine.disable_rule("PHISH-AUTH-001")
        engine.enable_rule("PHISH-AUTH-001")
        matches = engine.evaluate(_ctx(auth={"spf_status": "fail"}))
        ids = [m["rule_id"] for m in matches]
        assert "PHISH-AUTH-001" in ids

    def test_rule_exception_handled(self):
        engine = PhishingRuleEngine()

        def bad_rule(ctx):
            raise ValueError("boom")

        engine.add_rule(bad_rule)
        # Should not raise
        matches = engine.evaluate(_ctx())
        assert isinstance(matches, list)
