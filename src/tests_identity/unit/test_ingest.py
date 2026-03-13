"""Unit tests for the ingest_identity_events node (FR-01)."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.nodes.ingest import ingest_identity_events


class TestIngestIdentityEvents:
    """Verify normalisation of raw auth events and role changes."""

    def test_empty_input_produces_empty_output(self, empty_state: dict[str, Any]):
        result = ingest_identity_events(empty_state)
        assert result["raw_auth_events"] == []
        assert result["raw_role_changes"] == []
        assert result["batch_id"].startswith("iam-")

    def test_batch_id_assigned(self, normal_auth_events: list[dict]):
        state = {"raw_auth_events": normal_auth_events, "raw_role_changes": []}
        result = ingest_identity_events(state)
        assert result["batch_id"].startswith("iam-")
        for evt in result["raw_auth_events"]:
            assert evt["_batch_id"] == result["batch_id"]

    def test_preserves_existing_batch_id(self, normal_auth_events: list[dict]):
        state = {
            "raw_auth_events": normal_auth_events[:2],
            "raw_role_changes": [],
            "batch_id": "iam-test-12345",
        }
        result = ingest_identity_events(state)
        assert result["batch_id"] == "iam-test-12345"

    def test_auth_event_normalised_fields(self, normal_auth_events: list[dict]):
        state = {"raw_auth_events": normal_auth_events[:1], "raw_role_changes": []}
        result = ingest_identity_events(state)
        evt = result["raw_auth_events"][0]
        required_fields = [
            "event_id", "user_id", "username", "outcome", "mfa_method",
            "mfa_passed", "source_ip", "geo_latitude", "geo_longitude",
            "geo_city", "geo_country", "device_id", "device_type",
            "user_agent", "application", "timestamp", "_batch_id",
        ]
        for field in required_fields:
            assert field in evt, f"Missing field: {field}"

    def test_event_ids_assigned(self):
        """Events without event_id get one generated."""
        state = {
            "raw_auth_events": [{"user_id": "U1", "username": "test"}],
            "raw_role_changes": [{"user_id": "U2", "username": "test2", "role_name": "viewer"}],
        }
        result = ingest_identity_events(state)
        assert result["raw_auth_events"][0]["event_id"].startswith("auth-")
        assert result["raw_role_changes"][0]["event_id"].startswith("role-")

    def test_preserves_existing_event_id(self):
        state = {
            "raw_auth_events": [{"event_id": "auth-existing", "user_id": "U1"}],
            "raw_role_changes": [],
        }
        result = ingest_identity_events(state)
        assert result["raw_auth_events"][0]["event_id"] == "auth-existing"

    def test_role_change_normalised_fields(self, normal_role_changes: list[dict]):
        state = {"raw_auth_events": [], "raw_role_changes": normal_role_changes[:1]}
        result = ingest_identity_events(state)
        role = result["raw_role_changes"][0]
        required_fields = [
            "event_id", "user_id", "username", "action", "role_name",
            "role_risk_level", "changed_by", "justification", "timestamp", "_batch_id",
        ]
        for field in required_fields:
            assert field in role, f"Missing field: {field}"

    def test_defaults_for_missing_fields(self):
        """Ensure defaults are applied for missing optional fields."""
        state = {
            "raw_auth_events": [{"user_id": "U1"}],
            "raw_role_changes": [{"user_id": "U2"}],
        }
        result = ingest_identity_events(state)
        auth = result["raw_auth_events"][0]
        assert auth["outcome"] == "success"
        assert auth["mfa_method"] == "none"
        assert auth["mfa_passed"] is True

        role = result["raw_role_changes"][0]
        assert role["action"] == "role_assigned"
        assert role["role_risk_level"] == "low"

    def test_geo_coordinates_cast_to_float(self):
        state = {
            "raw_auth_events": [{"user_id": "U1", "geo_latitude": "40.7", "geo_longitude": "-74"}],
            "raw_role_changes": [],
        }
        result = ingest_identity_events(state)
        evt = result["raw_auth_events"][0]
        assert isinstance(evt["geo_latitude"], float)
        assert isinstance(evt["geo_longitude"], float)

    def test_multiple_auth_and_role_events(
        self,
        normal_auth_events: list[dict],
        normal_role_changes: list[dict],
    ):
        state = {
            "raw_auth_events": normal_auth_events,
            "raw_role_changes": normal_role_changes,
        }
        result = ingest_identity_events(state)
        assert len(result["raw_auth_events"]) == len(normal_auth_events)
        assert len(result["raw_role_changes"]) == len(normal_role_changes)
