"""Unit tests for the detect_takeover_signals node (FR-03)."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.nodes.takeover import detect_takeover_signals


class TestDetectTakeoverSignals:
    """Verify credential-stuffing, MFA fatigue, and brute-force detection."""

    def test_empty_input(self, empty_state: dict[str, Any]):
        result = detect_takeover_signals(empty_state)
        assert result["takeover_signals"] == []

    def test_normal_events_no_signals(self, normal_auth_events: list[dict]):
        state = {"raw_auth_events": normal_auth_events, "session_profiles": []}
        result = detect_takeover_signals(state)
        assert result["takeover_signals"] == []

    def test_brute_force_detected(self, brute_force_events: list[dict]):
        state = {"raw_auth_events": brute_force_events, "session_profiles": []}
        result = detect_takeover_signals(state)
        signal_types = {s["signal_type"] for s in result["takeover_signals"]}
        assert "brute_force" in signal_types

    def test_brute_force_threshold(self):
        """Exactly 4 failures should NOT trigger brute force (threshold is 5)."""
        from tests_identity.mocks.generators import generate_brute_force_events
        events = generate_brute_force_events(failure_count=4)
        state = {"raw_auth_events": events, "session_profiles": []}
        result = detect_takeover_signals(state)
        signal_types = {s["signal_type"] for s in result["takeover_signals"]}
        assert "brute_force" not in signal_types

    def test_brute_force_exactly_5(self):
        """Exactly 5 failures should trigger brute force."""
        from tests_identity.mocks.generators import generate_brute_force_events
        events = generate_brute_force_events(failure_count=5)
        state = {"raw_auth_events": events, "session_profiles": []}
        result = detect_takeover_signals(state)
        signal_types = {s["signal_type"] for s in result["takeover_signals"]}
        assert "brute_force" in signal_types

    def test_brute_force_confidence_scales(self):
        """More failures should increase confidence."""
        from tests_identity.mocks.generators import generate_brute_force_events
        events_5 = generate_brute_force_events(failure_count=5)
        events_15 = generate_brute_force_events(failure_count=15)

        result_5 = detect_takeover_signals({"raw_auth_events": events_5, "session_profiles": []})
        result_15 = detect_takeover_signals({"raw_auth_events": events_15, "session_profiles": []})

        bf_5 = [s for s in result_5["takeover_signals"] if s["signal_type"] == "brute_force"][0]
        bf_15 = [s for s in result_15["takeover_signals"] if s["signal_type"] == "brute_force"][0]
        assert bf_15["confidence"] > bf_5["confidence"]

    def test_mfa_fatigue_detected(self, mfa_fatigue_events: list[dict]):
        state = {"raw_auth_events": mfa_fatigue_events, "session_profiles": []}
        result = detect_takeover_signals(state)
        signal_types = {s["signal_type"] for s in result["takeover_signals"]}
        assert "mfa_fatigue" in signal_types

    def test_mfa_fatigue_is_critical(self, mfa_fatigue_events: list[dict]):
        state = {"raw_auth_events": mfa_fatigue_events, "session_profiles": []}
        result = detect_takeover_signals(state)
        mfa = [s for s in result["takeover_signals"] if s["signal_type"] == "mfa_fatigue"]
        assert all(s["severity"] == "critical" for s in mfa)

    def test_mfa_fatigue_below_threshold(self):
        """4 MFA denials should NOT trigger (threshold is 5)."""
        from tests_identity.mocks.generators import generate_mfa_fatigue_events
        events = generate_mfa_fatigue_events(denial_count=4)
        state = {"raw_auth_events": events, "session_profiles": []}
        result = detect_takeover_signals(state)
        signal_types = {s["signal_type"] for s in result["takeover_signals"]}
        assert "mfa_fatigue" not in signal_types

    def test_mfa_bypass_detected(self, mfa_bypass_events: list[dict]):
        state = {"raw_auth_events": mfa_bypass_events, "session_profiles": []}
        result = detect_takeover_signals(state)
        signal_types = {s["signal_type"] for s in result["takeover_signals"]}
        assert "mfa_bypass_suspected" in signal_types

    def test_mfa_bypass_is_critical(self, mfa_bypass_events: list[dict]):
        state = {"raw_auth_events": mfa_bypass_events, "session_profiles": []}
        result = detect_takeover_signals(state)
        bypass = [s for s in result["takeover_signals"] if s["signal_type"] == "mfa_bypass_suspected"]
        assert all(s["severity"] == "critical" for s in bypass)

    def test_account_lockout_detected(self, lockout_events: list[dict]):
        state = {"raw_auth_events": lockout_events, "session_profiles": []}
        result = detect_takeover_signals(state)
        signal_types = {s["signal_type"] for s in result["takeover_signals"]}
        assert "account_lockout" in signal_types

    def test_impossible_travel_with_failures(self, impossible_travel_events: list[dict]):
        """Impossible travel + failures should trigger combined signal."""
        user_id = impossible_travel_events[0]["user_id"]
        # Add a failure event
        failure = dict(impossible_travel_events[0])
        failure["outcome"] = "failure"
        all_events = impossible_travel_events + [failure]
        profiles = [{"user_id": user_id, "is_impossible_travel": True}]
        state = {"raw_auth_events": all_events, "session_profiles": profiles}
        result = detect_takeover_signals(state)
        signal_types = {s["signal_type"] for s in result["takeover_signals"]}
        assert "impossible_travel_with_failures" in signal_types

    def test_signal_fields(self, brute_force_events: list[dict]):
        state = {"raw_auth_events": brute_force_events, "session_profiles": []}
        result = detect_takeover_signals(state)
        signal = result["takeover_signals"][0]
        for field in ["user_id", "username", "signal_type", "severity", "confidence", "evidence", "source_event_id"]:
            assert field in signal, f"Missing field: {field}"
