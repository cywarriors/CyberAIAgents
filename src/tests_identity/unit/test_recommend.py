"""Unit tests for the recommend_controls node (FR-06/08)."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.nodes.recommend import recommend_controls


class TestRecommendControls:
    """Verify risk-to-control mapping."""

    def test_empty_input(self, empty_state: dict[str, Any]):
        result = recommend_controls(empty_state)
        assert result["recommendations"] == []

    def test_critical_risk_gets_session_kill(self):
        state = {
            "risk_scores": [{"user_id": "U1", "username": "test", "risk_level": "critical", "risk_score": 90.0}],
            "sod_violations": [],
        }
        result = recommend_controls(state)
        rec = result["recommendations"][0]
        assert rec["control"] == "session_kill"
        assert rec["requires_approval"] is True
        assert rec["auto_enforce"] is False

    def test_high_risk_gets_step_up_mfa(self):
        state = {
            "risk_scores": [{"user_id": "U1", "username": "test", "risk_level": "high", "risk_score": 70.0}],
            "sod_violations": [],
        }
        result = recommend_controls(state)
        rec = result["recommendations"][0]
        assert rec["control"] == "step_up_mfa"
        assert rec["auto_enforce"] is True

    def test_medium_risk_gets_monitor(self):
        state = {
            "risk_scores": [{"user_id": "U1", "username": "test", "risk_level": "medium", "risk_score": 50.0}],
            "sod_violations": [],
        }
        result = recommend_controls(state)
        rec = result["recommendations"][0]
        assert rec["control"] == "monitor"

    def test_low_risk_gets_no_action(self):
        state = {
            "risk_scores": [{"user_id": "U1", "username": "test", "risk_level": "low", "risk_score": 10.0}],
            "sod_violations": [],
        }
        result = recommend_controls(state)
        rec = result["recommendations"][0]
        assert rec["control"] == "no_action"

    def test_sod_adds_access_review(self):
        state = {
            "risk_scores": [],
            "sod_violations": [{
                "user_id": "U2", "username": "bob",
                "rule_name": "SoD: admin + auditor",
                "recommendation": "Remove one role",
            }],
        }
        result = recommend_controls(state)
        reviews = [r for r in result["recommendations"] if r["control"] == "access_review"]
        assert len(reviews) >= 1
        assert reviews[0]["user_id"] == "U2"

    def test_sod_not_duplicated_if_critical(self):
        """If user already has session_kill, skip SoD access_review."""
        state = {
            "risk_scores": [{"user_id": "U1", "username": "test", "risk_level": "critical", "risk_score": 90.0}],
            "sod_violations": [{
                "user_id": "U1", "username": "test",
                "rule_name": "SoD", "recommendation": "remove",
            }],
        }
        result = recommend_controls(state)
        user_recs = [r for r in result["recommendations"] if r["user_id"] == "U1"]
        # Should only have session_kill, not access_review
        controls = {r["control"] for r in user_recs}
        assert "session_kill" in controls
        assert "access_review" not in controls

    def test_recommendation_fields(self):
        state = {
            "risk_scores": [{"user_id": "U1", "username": "test", "risk_level": "high", "risk_score": 70.0}],
            "sod_violations": [],
        }
        result = recommend_controls(state)
        rec = result["recommendations"][0]
        for field in ["user_id", "username", "control", "reason", "risk_score", "risk_level", "auto_enforce", "requires_approval", "timestamp"]:
            assert field in rec, f"Missing field: {field}"

    def test_multiple_users(self):
        state = {
            "risk_scores": [
                {"user_id": "U1", "username": "alice", "risk_level": "critical", "risk_score": 90.0},
                {"user_id": "U2", "username": "bob", "risk_level": "low", "risk_score": 10.0},
            ],
            "sod_violations": [],
        }
        result = recommend_controls(state)
        assert len(result["recommendations"]) == 2
