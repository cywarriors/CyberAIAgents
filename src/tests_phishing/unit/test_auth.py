"""Unit tests for validate_sender_auth node (FR-02)."""

from phishing_defense_agent.nodes.auth import validate_sender_auth
from phishing_defense_agent.nodes.extract import extract_email_features
from tests_phishing.mocks.generators import (
    generate_clean_internal_email,
    generate_credential_harvest_email,
    generate_lookalike_domain_email,
    generate_bec_email,
    generate_new_domain_email,
)


def _features(email: dict) -> dict:
    return extract_email_features({"raw_emails": [email]})


class TestValidateSenderAuth:
    def test_spf_pass_for_clean(self):
        state = _features(generate_clean_internal_email())
        result = validate_sender_auth(state)
        assert len(result["auth_results"]) == 1
        assert result["auth_results"][0]["spf_status"] == "pass"

    def test_spf_fail_for_phishing(self):
        state = _features(generate_credential_harvest_email())
        result = validate_sender_auth(state)
        auth = result["auth_results"][0]
        assert auth["spf_status"] == "fail"

    def test_dkim_pass_for_clean(self):
        state = _features(generate_clean_internal_email())
        result = validate_sender_auth(state)
        assert result["auth_results"][0]["dkim_status"] == "pass"

    def test_dkim_fail_for_phishing(self):
        state = _features(generate_credential_harvest_email())
        result = validate_sender_auth(state)
        assert result["auth_results"][0]["dkim_status"] == "fail"

    def test_dmarc_pass_for_clean(self):
        state = _features(generate_clean_internal_email())
        result = validate_sender_auth(state)
        assert result["auth_results"][0]["dmarc_status"] == "pass"

    def test_dmarc_fail_for_phishing(self):
        state = _features(generate_credential_harvest_email())
        result = validate_sender_auth(state)
        assert result["auth_results"][0]["dmarc_status"] == "fail"

    def test_detects_lookalike_domain(self):
        state = _features(generate_lookalike_domain_email())
        result = validate_sender_auth(state)
        auth = result["auth_results"][0]
        assert auth["is_lookalike_domain"] is True
        assert auth["lookalike_target"]

    def test_no_lookalike_for_clean(self):
        state = _features(generate_clean_internal_email())
        result = validate_sender_auth(state)
        assert result["auth_results"][0]["is_lookalike_domain"] is False

    def test_high_reputation_for_clean(self):
        state = _features(generate_clean_internal_email())
        result = validate_sender_auth(state)
        assert result["auth_results"][0]["sender_reputation_score"] >= 70

    def test_low_reputation_for_phishing(self):
        state = _features(generate_credential_harvest_email())
        result = validate_sender_auth(state)
        assert result["auth_results"][0]["sender_reputation_score"] <= 30

    def test_auth_summary_for_clean(self):
        state = _features(generate_clean_internal_email())
        result = validate_sender_auth(state)
        assert result["auth_results"][0]["auth_summary"] == "All checks passed"

    def test_auth_summary_for_phishing(self):
        state = _features(generate_credential_harvest_email())
        result = validate_sender_auth(state)
        summary = result["auth_results"][0]["auth_summary"]
        assert "FAIL" in summary

    def test_message_id_preserved(self):
        email = generate_clean_internal_email()
        state = _features(email)
        msg_id = state["email_features"][0]["message_id"]
        result = validate_sender_auth(state)
        assert result["auth_results"][0]["message_id"] == msg_id

    def test_handles_empty_features(self):
        result = validate_sender_auth({"email_features": []})
        assert result["auth_results"] == []

    def test_bec_auth_failure(self):
        state = _features(generate_bec_email())
        result = validate_sender_auth(state)
        auth = result["auth_results"][0]
        assert auth["spf_status"] == "fail"
        assert auth["dmarc_status"] == "fail"

    def test_new_domain_low_reputation(self):
        email = generate_new_domain_email()
        state = _features(email)
        # Inject domain_age_days into features
        state["email_features"][0]["domain_age_days"] = 3
        result = validate_sender_auth(state)
        auth = result["auth_results"][0]
        assert auth["sender_reputation_score"] <= 30

    def test_multiple_emails(self):
        emails = [generate_clean_internal_email(), generate_credential_harvest_email()]
        state = extract_email_features({"raw_emails": emails})
        result = validate_sender_auth(state)
        assert len(result["auth_results"]) == 2
        assert result["auth_results"][0]["spf_status"] == "pass"
        assert result["auth_results"][1]["spf_status"] == "fail"
