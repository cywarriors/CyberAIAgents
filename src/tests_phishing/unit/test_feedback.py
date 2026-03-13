"""Unit tests for learn_from_release node (FR-10)."""

from __future__ import annotations

from phishing_defense_agent.nodes.feedback import learn_from_release


class TestLearnFromRelease:
    def test_returns_feedback_queue(self):
        state = {
            "feedback_queue": [{"message_id": "m1", "analyst_verdict": "false_positive"}],
            "verdicts": [],
        }
        result = learn_from_release(state)
        assert result["feedback_queue"] == state["feedback_queue"]

    def test_empty_feedback_queue(self):
        result = learn_from_release({"feedback_queue": [], "verdicts": []})
        assert result["feedback_queue"] == []

    def test_preserves_analyst_feedback(self):
        feedback = [
            {"message_id": "m1", "analyst_verdict": "true_positive"},
            {"message_id": "m2", "analyst_verdict": "false_positive"},
        ]
        state = {"feedback_queue": feedback, "verdicts": []}
        result = learn_from_release(state)
        assert len(result["feedback_queue"]) == 2

    def test_handles_missing_feedback_key(self):
        result = learn_from_release({"verdicts": []})
        assert result["feedback_queue"] == []

    def test_handles_verdicts_stats(self):
        state = {
            "feedback_queue": [],
            "verdicts": [
                {"action": "block"},
                {"action": "quarantine"},
                {"action": "allow"},
            ],
        }
        result = learn_from_release(state)
        assert "feedback_queue" in result
