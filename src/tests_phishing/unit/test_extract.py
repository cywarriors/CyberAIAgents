"""Unit tests for extract_email_features node (FR-01)."""

from phishing_defense_agent.nodes.extract import extract_email_features
from tests_phishing.mocks.generators import (
    generate_clean_internal_email,
    generate_credential_harvest_email,
    generate_malware_delivery_email,
    generate_url_phishing_email,
)


class TestExtractEmailFeatures:
    def test_assigns_batch_id(self):
        email = generate_clean_internal_email()
        result = extract_email_features({"raw_emails": [email]})
        assert result["batch_id"]
        assert result["batch_id"].startswith("phish-")

    def test_preserves_email_count(self):
        emails = [generate_clean_internal_email(), generate_credential_harvest_email()]
        result = extract_email_features({"raw_emails": emails})
        assert len(result["email_features"]) == 2

    def test_handles_empty_list(self):
        result = extract_email_features({"raw_emails": []})
        assert result["email_features"] == []
        assert result["batch_id"]

    def test_extracts_urls_from_body(self):
        email = generate_url_phishing_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert len(feat["urls"]) >= 1

    def test_detects_shortened_urls(self):
        email = generate_url_phishing_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert feat["has_shortened_urls"] is True

    def test_extracts_sender_domain(self):
        email = generate_credential_harvest_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert feat["sender_domain"]
        assert "." in feat["sender_domain"]

    def test_extracts_subject(self):
        email = generate_credential_harvest_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert feat["subject"] == email["subject"]

    def test_extracts_attachment_info(self):
        email = generate_malware_delivery_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert feat["attachment_count"] >= 1
        assert len(feat["attachment_names"]) >= 1

    def test_assigns_message_id(self):
        email = {"from": "test@example.com", "to": "user@acme.com", "subject": "Test", "body": ""}
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert feat["message_id"].startswith("msg-")

    def test_preserves_existing_message_id(self):
        email = generate_clean_internal_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert feat["message_id"] == email["message_id"]

    def test_stamps_processed_at(self):
        email = generate_clean_internal_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert "_processed_at" in feat

    def test_detects_internal_email(self):
        email = generate_clean_internal_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert feat["is_internal"] is True

    def test_detects_external_email(self):
        email = generate_credential_harvest_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert feat["is_internal"] is False

    def test_handles_string_to_field(self):
        email = {"from": "a@test.com", "to": "b@test.com,c@test.com", "body": "hello", "subject": "x"}
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert len(feat["recipient_addresses"]) == 2

    def test_url_deduplication(self):
        email = {
            "from": "a@test.com",
            "to": "b@test.com",
            "subject": "test",
            "body": "https://example.com https://example.com",
        }
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert feat["urls"].count("https://example.com") == 1

    def test_headers_preserved(self):
        email = generate_credential_harvest_email()
        result = extract_email_features({"raw_emails": [email]})
        feat = result["email_features"][0]
        assert "Authentication-Results" in feat["headers"]
