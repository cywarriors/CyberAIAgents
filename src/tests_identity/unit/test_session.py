"""Unit tests for the analyze_session_patterns node (FR-02)."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.nodes.session import (
    analyze_session_patterns,
    _haversine,
    _is_off_hours,
)


class TestHaversine:
    """Verify great-circle distance calculation."""

    def test_same_point_returns_zero(self):
        assert _haversine(40.7128, -74.0060, 40.7128, -74.0060) == pytest.approx(0.0, abs=0.01)

    def test_nyc_to_london(self):
        dist = _haversine(40.7128, -74.0060, 51.5074, -0.1278)
        assert 5500 < dist < 5700  # ~5,570 km

    def test_nyc_to_tokyo(self):
        dist = _haversine(40.7128, -74.0060, 35.6762, 139.6503)
        assert 10_000 < dist < 11_000  # ~10,850 km


class TestIsOffHours:
    """Verify off-hours detection."""

    def test_business_hours(self):
        assert _is_off_hours("2025-01-15T10:30:00+00:00") is False

    def test_early_morning(self):
        assert _is_off_hours("2025-01-15T03:00:00+00:00") is True

    def test_late_evening(self):
        assert _is_off_hours("2025-01-15T22:00:00+00:00") is True

    def test_boundary_8am(self):
        assert _is_off_hours("2025-01-15T08:00:00+00:00") is False

    def test_boundary_6pm(self):
        assert _is_off_hours("2025-01-15T18:00:00+00:00") is True

    def test_invalid_timestamp(self):
        assert _is_off_hours("not-a-timestamp") is False


class TestAnalyzeSessionPatterns:
    """Verify session anomaly detection."""

    def test_empty_events(self, empty_state: dict[str, Any]):
        result = analyze_session_patterns(empty_state)
        assert result["session_profiles"] == []
        assert result["session_anomalies"] == []

    def test_normal_events_no_anomalies(self, normal_auth_events: list[dict]):
        # Normal events: same location, same device, business hours
        state = {"raw_auth_events": normal_auth_events}
        result = analyze_session_patterns(state)
        assert len(result["session_profiles"]) > 0
        anomaly_types = {a["anomaly_type"] for a in result["session_anomalies"]}
        assert "impossible_travel" not in anomaly_types

    def test_impossible_travel_detected(self, impossible_travel_events: list[dict]):
        state = {"raw_auth_events": impossible_travel_events}
        result = analyze_session_patterns(state)
        anomaly_types = {a["anomaly_type"] for a in result["session_anomalies"]}
        assert "impossible_travel" in anomaly_types

    def test_impossible_travel_evidence(self, impossible_travel_events: list[dict]):
        state = {"raw_auth_events": impossible_travel_events}
        result = analyze_session_patterns(state)
        travel_anomalies = [
            a for a in result["session_anomalies"]
            if a["anomaly_type"] == "impossible_travel"
        ]
        assert len(travel_anomalies) >= 1
        assert "km" in travel_anomalies[0]["evidence"]
        assert travel_anomalies[0]["severity"] == "high"

    def test_impossible_travel_skips_vpn(self):
        """Travel events with VPN IP should not trigger impossible travel."""
        from tests_identity.mocks.generators import generate_impossible_travel_with_vpn
        events = generate_impossible_travel_with_vpn()
        state = {"raw_auth_events": events}
        result = analyze_session_patterns(state)
        anomaly_types = {a["anomaly_type"] for a in result["session_anomalies"]}
        assert "impossible_travel" not in anomaly_types

    def test_off_hours_detected(self, off_hours_events: list[dict]):
        state = {"raw_auth_events": off_hours_events}
        result = analyze_session_patterns(state)
        anomaly_types = {a["anomaly_type"] for a in result["session_anomalies"]}
        assert "off_hours_login" in anomaly_types

    def test_off_hours_one_per_user(self, off_hours_events: list[dict]):
        """Only one off-hours anomaly per user per batch."""
        state = {"raw_auth_events": off_hours_events}
        result = analyze_session_patterns(state)
        off_hours = [a for a in result["session_anomalies"] if a["anomaly_type"] == "off_hours_login"]
        user_ids = [a["user_id"] for a in off_hours]
        assert len(user_ids) == len(set(user_ids)), "Should only generate one off-hours anomaly per user"

    def test_new_device_detected(self, new_device_events: list[dict]):
        state = {"raw_auth_events": new_device_events}
        result = analyze_session_patterns(state)
        anomaly_types = {a["anomaly_type"] for a in result["session_anomalies"]}
        assert "new_device" in anomaly_types

    def test_new_device_evidence(self, new_device_events: list[dict]):
        state = {"raw_auth_events": new_device_events}
        result = analyze_session_patterns(state)
        new_dev = [a for a in result["session_anomalies"] if a["anomaly_type"] == "new_device"]
        assert len(new_dev) >= 1
        assert "DEV-" in new_dev[0]["evidence"]

    def test_session_profile_fields(self, normal_auth_events: list[dict]):
        state = {"raw_auth_events": normal_auth_events[:2]}
        result = analyze_session_patterns(state)
        profile = result["session_profiles"][0]
        expected_fields = [
            "user_id", "username", "login_count_24h", "failed_login_count_24h",
            "mfa_denied_count_1h", "unique_ips_24h", "unique_devices_24h",
            "is_impossible_travel", "travel_speed_kmh", "is_new_device", "is_off_hours",
        ]
        for f in expected_fields:
            assert f in profile, f"Missing profile field: {f}"

    def test_profile_counts(self, brute_force_events: list[dict]):
        state = {"raw_auth_events": brute_force_events}
        result = analyze_session_patterns(state)
        # brute_force_events are all for one user
        profile = result["session_profiles"][0]
        assert profile["failed_login_count_24h"] == 8  # 8 failures
        assert profile["login_count_24h"] == 9  # 8 failures + 1 success
