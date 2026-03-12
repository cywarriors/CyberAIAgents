"""Integration test – full end-to-end triage pipeline with mock alerts (§14)."""

import pytest
from tests_triage.mocks.generators import (
    generate_mixed_alert_batch,
    generate_all_attack_alerts,
    generate_benign_auth_alert,
    generate_benign_network_alert,
    generate_multi_stage_intrusion,
)
from incident_triage_agent.nodes.ingest import ingest_alert
from incident_triage_agent.nodes.correlate import correlate_incident
from incident_triage_agent.nodes.enrich import enrich_entity
from incident_triage_agent.nodes.risk_score import risk_score
from incident_triage_agent.nodes.summarize import generate_summary
from incident_triage_agent.nodes.recommend import recommend_actions
from incident_triage_agent.nodes.case_manager import create_or_update_case
from incident_triage_agent.nodes.feedback import feedback_learn


def _run_pipeline(raw_alerts: list[dict]) -> dict:
    """Execute all triage pipeline stages sequentially."""
    # 1. Ingest
    state: dict = {"raw_alerts": raw_alerts}
    ingest_out = ingest_alert(state)
    state.update(ingest_out)

    # 2. Correlate
    corr_out = correlate_incident(state)
    state.update(corr_out)

    # 3. Enrich
    enrich_out = enrich_entity(state)
    state.update(enrich_out)

    # 4. Risk score
    score_out = risk_score(state)
    state.update(score_out)

    # 5. Summarize
    summary_out = generate_summary(state)
    state.update(summary_out)

    # 6. Recommend
    rec_out = recommend_actions(state)
    state.update(rec_out)

    # 7. Case manager
    case_out = create_or_update_case(state)
    state.update(case_out)

    # 8. Feedback
    fb_out = feedback_learn(state)
    state.update(fb_out)

    return state


@pytest.mark.integration
class TestFullTriagePipeline:
    def test_mixed_batch_produces_incidents(self):
        """A mixed batch with 30% attacks should produce triaged incidents."""
        alerts = generate_mixed_alert_batch(total=30, attack_ratio=0.3, seed=42)
        state = _run_pipeline(alerts)
        assert len(state["triaged_incidents"]) > 0

    def test_benign_batch_still_produces_cases(self):
        """Even benign alerts go through triage — they just get low priority."""
        alerts = [generate_benign_auth_alert() for _ in range(5)] + \
                 [generate_benign_network_alert() for _ in range(5)]
        state = _run_pipeline(alerts)
        assert len(state["triaged_incidents"]) > 0
        # Should get low priority
        for inc in state["triaged_incidents"]:
            assert inc["priority"] in ("P3", "P4")

    def test_multi_stage_attack_gets_high_priority(self):
        """A multi-stage attack chain should be triaged as P1 or P2."""
        alerts = generate_multi_stage_intrusion()
        state = _run_pipeline(alerts)
        assert len(state["triaged_incidents"]) == 1
        inc = state["triaged_incidents"][0]
        assert inc["priority"] in ("P1", "P2")

    def test_all_incidents_have_required_fields(self):
        """Every triaged incident must include the required data fields."""
        alerts = generate_all_attack_alerts()
        state = _run_pipeline(alerts)
        for inc in state["triaged_incidents"]:
            assert inc.get("incident_id")
            assert inc.get("case_id")
            assert inc.get("priority") in ("P1", "P2", "P3", "P4")
            assert inc.get("classification")
            assert inc.get("severity")
            assert inc.get("triage_summary")
            assert inc.get("alert_ids")
            assert inc.get("timeline")
            assert inc.get("mitre_technique_ids") is not None
            assert inc.get("mitre_tactics") is not None

    def test_pipeline_handles_empty_batch(self):
        state = _run_pipeline([])
        assert state["triaged_incidents"] == []

    def test_pipeline_assigns_batch_id(self):
        alerts = generate_all_attack_alerts()
        state = _run_pipeline(alerts)
        assert state["triage_batch_id"].startswith("triage-")

    def test_entity_enrichment_present(self):
        """All triaged incidents should have entity profiles."""
        alerts = generate_multi_stage_intrusion()
        state = _run_pipeline(alerts)
        inc = state["triaged_incidents"][0]
        assert len(inc["entity_profiles"]) > 0

    def test_recommended_actions_present(self):
        """Triaged incidents from attacks should have recommended actions."""
        alerts = generate_multi_stage_intrusion()
        state = _run_pipeline(alerts)
        inc = state["triaged_incidents"][0]
        assert len(inc["recommended_actions"]) > 0

    def test_correlation_groups_exist(self):
        """Pipeline should produce correlation groups."""
        alerts = generate_multi_stage_intrusion()
        state = _run_pipeline(alerts)
        assert len(state["correlations"]) > 0
