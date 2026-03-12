"""Unit tests for Node 9 – PublishFindings."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from vapt_agent.nodes.publish_findings import publish_findings


class TestPublishFindings:
    """Test suite for publish findings node."""

    @patch("vapt_agent.nodes.publish_findings.send_notification", return_value=True)
    @patch("vapt_agent.nodes.publish_findings.create_ticket", return_value="TKT-001")
    def test_publishes_all_scored_findings(self, mock_ticket, mock_notify, full_state):
        from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
        from vapt_agent.nodes.generate_remediation import generate_remediation
        scored_state = {**full_state, **score_and_prioritize(full_state)}
        remed_state = {**scored_state, **generate_remediation(scored_state)}

        result = publish_findings(remed_state)
        published = result.get("published_findings", [])
        assert len(published) == len(remed_state["risk_scores"])

    @patch("vapt_agent.nodes.publish_findings.send_notification", return_value=True)
    @patch("vapt_agent.nodes.publish_findings.create_ticket", return_value="TKT-002")
    def test_creates_tickets(self, mock_ticket, mock_notify, full_state):
        from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
        scored_state = {**full_state, **score_and_prioritize(full_state)}

        result = publish_findings(scored_state)
        published = result["published_findings"]
        assert all(p.get("ticket_id") == "TKT-002" for p in published)
        assert mock_ticket.call_count == len(scored_state["risk_scores"])

    @patch("vapt_agent.nodes.publish_findings.send_notification", return_value=True)
    @patch("vapt_agent.nodes.publish_findings.create_ticket", return_value=None)
    def test_sends_summary_notification(self, mock_ticket, mock_notify, full_state):
        from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
        scored_state = {**full_state, **score_and_prioritize(full_state)}

        publish_findings(scored_state)
        mock_notify.assert_called_once()
        call_args = mock_notify.call_args[0][0]
        assert "engagement_id" in call_args

    @patch("vapt_agent.nodes.publish_findings.send_notification", return_value=True)
    @patch("vapt_agent.nodes.publish_findings.create_ticket", return_value=None)
    def test_empty_findings(self, mock_ticket, mock_notify):
        result = publish_findings({
            "risk_scores": [],
            "remediation_items": [],
            "engagement_id": "eng-empty",
        })
        assert result.get("published_findings", []) == []
        mock_ticket.assert_not_called()
