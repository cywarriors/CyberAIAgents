"""Unit tests for track_drift node."""


def _state_with_scores(scores: dict) -> dict:
    return {
        "evidence_items": [], "control_mappings": [], "effectiveness_scores": {},
        "gaps": [], "framework_scores": scores, "audit_packs": [],
        "drift_alerts": [], "remediation_tickets": [], "processing_errors": [],
    }


def test_track_drift_no_previous_no_alert():
    """First run with no stored previous scores should produce no alerts."""
    from compliance_audit_agent.nodes.track_drift import track_drift
    state = _state_with_scores({"ISO27001": {"score": 85.0}})
    result = track_drift(state)
    assert result["drift_alerts"] == []


def test_track_drift_stores_score_for_next_run():
    from compliance_audit_agent.nodes.track_drift import track_drift
    from compliance_audit_agent.monitoring.store import get_store
    state = _state_with_scores({"ISO27001": {"score": 90.0}})
    track_drift(state)
    assert get_store().get_previous_score("ISO27001") == 90.0


def test_track_drift_regression_triggers_alert():
    """A drop >= threshold should create a drift alert."""
    from compliance_audit_agent.nodes.track_drift import track_drift
    from compliance_audit_agent.monitoring.store import get_store
    store = get_store()
    store.save_score("ISO27001", 90.0)  # Previous = 90
    state = _state_with_scores({"ISO27001": {"score": 80.0}})  # Drop 11%
    result = track_drift(state)
    assert len(result["drift_alerts"]) == 1
    alert = result["drift_alerts"][0]
    assert alert["framework"] == "ISO27001"
    assert alert["delta_pct"] > 5.0


def test_track_drift_small_drop_no_alert():
    """A drop below threshold should not create an alert."""
    from compliance_audit_agent.nodes.track_drift import track_drift
    from compliance_audit_agent.monitoring.store import get_store
    get_store().save_score("NIST_CSF", 90.0)
    state = _state_with_scores({"NIST_CSF": {"score": 88.0}})  # Drop 2.2% < 5%
    result = track_drift(state)
    assert result["drift_alerts"] == []


def test_track_drift_alert_has_required_fields():
    from compliance_audit_agent.nodes.track_drift import track_drift
    from compliance_audit_agent.monitoring.store import get_store
    get_store().save_score("SOC2", 95.0)
    state = _state_with_scores({"SOC2": {"score": 70.0}})  # Drop 26%
    result = track_drift(state)
    assert len(result["drift_alerts"]) == 1
    for field in ("alert_id", "framework", "previous_score", "current_score", "delta_pct", "detected_at"):
        assert field in result["drift_alerts"][0]


def test_track_drift_returns_list(empty_state):
    from compliance_audit_agent.nodes.track_drift import track_drift
    state = _state_with_scores({})
    result = track_drift(state)
    assert isinstance(result["drift_alerts"], list)
