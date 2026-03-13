"""Unit tests for the feedback_and_policy_tune node (FR-10/12)."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.nodes.feedback import feedback_and_policy_tune


class TestFeedbackAndPolicyTune:
    """Verify feedback collection and passthrough."""

    def test_empty_input(self, empty_state: dict[str, Any]):
        result = feedback_and_policy_tune(empty_state)
        assert result["feedback_queue"] == []

    def test_passthrough_feedback(self):
        feedback_items = [
            {"alert_id": "A1", "verdict": "true_positive", "analyst_id": "SOC-01"},
            {"alert_id": "A2", "verdict": "false_positive", "analyst_id": "SOC-02"},
        ]
        state = {"feedback_queue": feedback_items, "alerts": []}
        result = feedback_and_policy_tune(state)
        assert result["feedback_queue"] == feedback_items

    def test_with_alerts(self):
        alerts = [
            {"alert_id": "A1", "severity": "high"},
            {"alert_id": "A2", "severity": "critical"},
            {"alert_id": "A3", "severity": "medium"},
        ]
        state = {"feedback_queue": [], "alerts": alerts}
        result = feedback_and_policy_tune(state)
        assert result["feedback_queue"] == []

    def test_no_crash_on_empty_alerts(self):
        state = {"feedback_queue": [], "alerts": []}
        result = feedback_and_policy_tune(state)
        assert "feedback_queue" in result
