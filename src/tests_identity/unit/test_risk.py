"""Unit tests for the compute_identity_risk node (FR-05)."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.nodes.risk import compute_identity_risk


def _build_risk_state(
    *,
    session_profiles: list[dict] | None = None,
    session_anomalies: list[dict] | None = None,
    privilege_alerts: list[dict] | None = None,
    sod_violations: list[dict] | None = None,
    takeover_signals: list[dict] | None = None,
    raw_auth_events: list[dict] | None = None,
) -> dict[str, Any]:
    return {
        "raw_auth_events": raw_auth_events or [],
        "session_profiles": session_profiles or [],
        "session_anomalies": session_anomalies or [],
        "privilege_alerts": privilege_alerts or [],
        "sod_violations": sod_violations or [],
        "takeover_signals": takeover_signals or [],
    }


class TestComputeIdentityRisk:
    """Verify weighted risk scoring."""

    def test_empty_input(self):
        result = compute_identity_risk(_build_risk_state())
        assert result["risk_scores"] == []

    def test_low_risk_for_clean_user(self):
        state = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
        )
        result = compute_identity_risk(state)
        score = result["risk_scores"][0]
        assert score["risk_level"] == "low"
        assert score["risk_score"] < 40

    def test_high_risk_from_takeover_signals(self):
        state = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
            takeover_signals=[{
                "user_id": "U1",
                "signal_type": "brute_force",
                "severity": "high",
                "evidence": "8 failed logins",
            }],
            raw_auth_events=[
                {"user_id": "U1", "outcome": "failure"} for _ in range(8)
            ],
        )
        result = compute_identity_risk(state)
        score = result["risk_scores"][0]
        assert score["risk_level"] in ("high", "critical")
        assert score["risk_score"] >= 40

    def test_critical_from_multiple_signals(self):
        state = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
            session_anomalies=[{
                "user_id": "U1", "anomaly_type": "impossible_travel",
                "severity": "high", "evidence": "Travel",
            }],
            takeover_signals=[{
                "user_id": "U1", "signal_type": "mfa_fatigue",
                "severity": "critical", "evidence": "MFA bombing",
            }],
            raw_auth_events=[{"user_id": "U1", "outcome": "failure"} for _ in range(5)],
        )
        result = compute_identity_risk(state)
        score = result["risk_scores"][0]
        assert score["risk_score"] >= 65

    def test_risk_score_capped_at_100(self):
        """Score should never exceed 100."""
        state = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
            session_anomalies=[
                {"user_id": "U1", "anomaly_type": "impossible_travel", "severity": "critical", "evidence": "x"}
                for _ in range(10)
            ],
            takeover_signals=[
                {"user_id": "U1", "signal_type": "brute_force", "severity": "critical", "evidence": "y"}
                for _ in range(10)
            ],
            privilege_alerts=[
                {"user_id": "U1", "alert_type": "self_escalation", "severity": "critical"}
                for _ in range(5)
            ],
            raw_auth_events=[{"user_id": "U1", "outcome": "failure"} for _ in range(20)],
        )
        result = compute_identity_risk(state)
        score = result["risk_scores"][0]
        assert score["risk_score"] <= 100.0

    def test_score_components_present(self):
        state = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
        )
        result = compute_identity_risk(state)
        score = result["risk_scores"][0]
        assert "components" in score
        expected_components = [
            "session_anomaly", "auth_failure", "privilege_change",
            "takeover_signals", "context_enrichment",
        ]
        for comp in expected_components:
            assert comp in score["components"]

    def test_explanation_present(self):
        state = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
        )
        result = compute_identity_risk(state)
        score = result["risk_scores"][0]
        assert "explanation" in score
        assert score["explanation"]

    def test_confidence_increases_with_signals(self):
        state_low = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
        )
        state_high = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
            session_anomalies=[
                {"user_id": "U1", "anomaly_type": "impossible_travel", "severity": "high", "evidence": "x"},
                {"user_id": "U1", "anomaly_type": "off_hours", "severity": "low", "evidence": "y"},
            ],
            takeover_signals=[
                {"user_id": "U1", "signal_type": "brute_force", "severity": "high", "evidence": "z"},
            ],
        )
        result_low = compute_identity_risk(state_low)
        result_high = compute_identity_risk(state_high)
        assert result_high["risk_scores"][0]["confidence"] > result_low["risk_scores"][0]["confidence"]

    def test_confidence_capped_at_099(self):
        state = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
            session_anomalies=[
                {"user_id": "U1", "anomaly_type": f"type_{i}", "severity": "high", "evidence": "x"}
                for i in range(20)
            ],
        )
        result = compute_identity_risk(state)
        assert result["risk_scores"][0]["confidence"] <= 0.99

    def test_multiple_users(self):
        state = _build_risk_state(
            session_profiles=[
                {"user_id": "U1", "username": "alice"},
                {"user_id": "U2", "username": "bob"},
            ],
        )
        result = compute_identity_risk(state)
        assert len(result["risk_scores"]) == 2
        user_ids = {s["user_id"] for s in result["risk_scores"]}
        assert user_ids == {"U1", "U2"}

    def test_sod_increases_risk(self):
        state_no_sod = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
        )
        state_with_sod = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
            sod_violations=[{
                "user_id": "U1", "conflicting_roles": ["admin", "auditor"],
                "rule_id": "SOD-001", "severity": "high",
            }],
        )
        r1 = compute_identity_risk(state_no_sod)
        r2 = compute_identity_risk(state_with_sod)
        assert r2["risk_scores"][0]["risk_score"] > r1["risk_scores"][0]["risk_score"]

    def test_indicators_list(self):
        state = _build_risk_state(
            session_profiles=[{"user_id": "U1", "username": "test"}],
            session_anomalies=[{
                "user_id": "U1", "anomaly_type": "impossible_travel",
                "severity": "high", "evidence": "Travel 10000km",
            }],
        )
        result = compute_identity_risk(state)
        indicators = result["risk_scores"][0]["indicators"]
        assert len(indicators) >= 1
        assert indicators[0]["type"] == "impossible_travel"
