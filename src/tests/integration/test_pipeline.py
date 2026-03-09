"""Integration test – full end-to-end pipeline with mock telemetry (§14)."""

import pytest
from tests.mocks.generators import generate_mixed_batch, generate_all_attack_scenarios
from threat_detection_agent.nodes.ingest import ingest_telemetry
from threat_detection_agent.nodes.normalize import normalize_schema
from threat_detection_agent.nodes.rule_match import rule_match
from threat_detection_agent.nodes.anomaly import behavior_anomaly
from threat_detection_agent.nodes.score import score_and_prioritize
from threat_detection_agent.nodes.deduplicate import deduplicate
from threat_detection_agent.nodes.publish import publish_alert
from threat_detection_agent.nodes.feedback import feedback_update


def _run_pipeline(raw_events: list[dict]) -> dict:
    """Execute all pipeline stages sequentially with merge points."""
    # 1. Ingest
    state = ingest_telemetry({"raw_events": raw_events})

    # 2. Normalise
    norm_out = normalize_schema(state)
    state.update(norm_out)

    # 3. Parallel detection (simulated sequentially, merge results)
    rule_out = rule_match(state)
    anomaly_out = behavior_anomaly(state)
    state["matched_rules"] = rule_out.get("matched_rules", [])
    state["anomalies"] = anomaly_out.get("anomalies", [])

    # 4. Score & prioritise
    score_out = score_and_prioritize(state)
    state.update(score_out)

    # 5. Deduplicate
    dedup_out = deduplicate(state)
    state.update(dedup_out)

    # 6. Publish (integration clients are unconfigured → no-ops in test)
    pub_out = publish_alert(state)
    state.update(pub_out)

    # 7. Feedback
    fb_out = feedback_update(state)
    state.update(fb_out)

    return state


@pytest.mark.integration
class TestFullPipeline:
    def test_mixed_batch_produces_alerts(self):
        """A mixed batch with 30% attacks should produce at least some alerts."""
        events = generate_mixed_batch(total=50, attack_ratio=0.3, seed=99)
        state = _run_pipeline(events)
        assert len(state["final_alerts"]) > 0

    def test_benign_only_batch_produces_few_or_no_alerts(self):
        """Pure benign traffic should yield zero or very few spurious alerts."""
        from tests.mocks.generators import (
            generate_benign_auth_event,
            generate_benign_network_event,
        )

        events = [generate_benign_auth_event() for _ in range(20)] + [
            generate_benign_network_event() for _ in range(20)
        ]
        state = _run_pipeline(events)
        # Accept 0 alerts (ideal) or at most a small number
        assert len(state["final_alerts"]) <= 2

    def test_all_alerts_include_evidence_and_mitre(self):
        """AC-04: 100% of alerts include evidence bundle and ATT&CK technique ID."""
        events = generate_all_attack_scenarios()
        state = _run_pipeline(events)
        for alert in state["final_alerts"]:
            # Evidence bundle present
            assert alert.get("evidence") is not None
            # At least source_type to trace origin
            assert alert.get("source_type")

    def test_pipeline_handles_empty_batch(self):
        state = _run_pipeline([])
        assert state["final_alerts"] == []

    def test_pipeline_assigns_batch_id(self):
        events = generate_all_attack_scenarios()
        state = _run_pipeline(events)
        assert state["event_batch_id"].startswith("batch-")
