"""Unit tests for the open_case_or_ticket node (FR-07/09)."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.nodes.alert import open_case_or_ticket


class TestOpenCaseOrTicket:
    """Verify alert generation based on risk scores."""

    def test_empty_input(self, empty_state: dict[str, Any]):
        result = open_case_or_ticket(empty_state)
        assert result["alerts"] == []

    def test_no_alerts_for_low_risk(self):
        state = {
            "risk_scores": [{"user_id": "U1", "username": "test", "risk_level": "low", "risk_score": 10.0}],
            "recommendations": [],
        }
        result = open_case_or_ticket(state)
        assert result["alerts"] == []

    def test_alert_for_critical_risk(self):
        state = {
            "risk_scores": [{
                "user_id": "U1", "username": "alice", "risk_level": "critical",
                "risk_score": 92.0, "indicators": [
                    {"type": "brute_force", "severity": "high", "evidence": "8 failures"},
                ],
            }],
            "recommendations": [{"user_id": "U1", "control": "session_kill"}],
        }
        result = open_case_or_ticket(state)
        assert len(result["alerts"]) == 1
        alert = result["alerts"][0]
        assert alert["severity"] == "critical"
        assert "CRITICAL" in alert["title"]
        assert alert["user_id"] == "U1"

    def test_alert_for_high_risk(self):
        state = {
            "risk_scores": [{
                "user_id": "U1", "username": "bob", "risk_level": "high",
                "risk_score": 72.0, "indicators": [],
            }],
            "recommendations": [{"user_id": "U1", "control": "step_up_mfa"}],
        }
        result = open_case_or_ticket(state)
        assert len(result["alerts"]) == 1
        assert "HIGH" in result["alerts"][0]["title"]

    def test_alert_for_medium_risk(self):
        state = {
            "risk_scores": [{
                "user_id": "U1", "username": "carol", "risk_level": "medium",
                "risk_score": 55.0, "indicators": [],
            }],
            "recommendations": [],
        }
        result = open_case_or_ticket(state)
        assert len(result["alerts"]) == 1
        assert "MEDIUM" in result["alerts"][0]["title"]

    def test_alert_fields(self):
        state = {
            "risk_scores": [{
                "user_id": "U1", "username": "test", "risk_level": "high",
                "risk_score": 70.0, "indicators": [],
            }],
            "recommendations": [{"user_id": "U1", "control": "step_up_mfa"}],
        }
        result = open_case_or_ticket(state)
        alert = result["alerts"][0]
        required_fields = [
            "alert_id", "user_id", "username", "severity", "title",
            "description", "risk_score", "indicators", "recommended_control",
            "status", "created_at", "ticket_id",
        ]
        for field in required_fields:
            assert field in alert, f"Missing field: {field}"

    def test_alert_id_format(self):
        state = {
            "risk_scores": [{
                "user_id": "U1", "username": "test", "risk_level": "high",
                "risk_score": 70.0, "indicators": [],
            }],
            "recommendations": [],
        }
        result = open_case_or_ticket(state)
        alert = result["alerts"][0]
        assert alert["alert_id"].startswith("iam-alert-")
        assert alert["ticket_id"].startswith("IAM-")

    def test_alert_status_is_open(self):
        state = {
            "risk_scores": [{
                "user_id": "U1", "username": "test", "risk_level": "critical",
                "risk_score": 95.0, "indicators": [],
            }],
            "recommendations": [],
        }
        result = open_case_or_ticket(state)
        assert result["alerts"][0]["status"] == "open"

    def test_multiple_alerts(self):
        state = {
            "risk_scores": [
                {"user_id": "U1", "username": "alice", "risk_level": "critical", "risk_score": 90.0, "indicators": []},
                {"user_id": "U2", "username": "bob", "risk_level": "high", "risk_score": 70.0, "indicators": []},
                {"user_id": "U3", "username": "carol", "risk_level": "low", "risk_score": 10.0, "indicators": []},
            ],
            "recommendations": [],
        }
        result = open_case_or_ticket(state)
        assert len(result["alerts"]) == 2  # critical + high, not low

    def test_description_includes_risk_score(self):
        state = {
            "risk_scores": [{
                "user_id": "U1", "username": "test", "risk_level": "high",
                "risk_score": 75.5, "indicators": [],
            }],
            "recommendations": [],
        }
        result = open_case_or_ticket(state)
        assert "75.5" in result["alerts"][0]["description"]
