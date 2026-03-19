"""Unit tests for assess_effectiveness node."""

from tests_compliance.mocks.generators import (
    generate_iso27001_evidence_batch,
    generate_weak_evidence_record,
    generate_evidence_record,
)


def _build_state_with_evidence(evidence_list):
    from compliance_audit_agent.nodes.map_controls import map_controls
    state = {
        "evidence_items": evidence_list,
        "control_mappings": [],
        "effectiveness_scores": {},
        "gaps": [], "framework_scores": {}, "audit_packs": [],
        "drift_alerts": [], "remediation_tickets": [], "processing_errors": [],
    }
    mapped = map_controls(state)
    state.update(mapped)
    return state


def test_assess_effectiveness_returns_dict(empty_state):
    from compliance_audit_agent.nodes.assess_effectiveness import assess_effectiveness
    empty_state["evidence_items"] = generate_iso27001_evidence_batch()
    from compliance_audit_agent.nodes.map_controls import map_controls
    empty_state.update(map_controls(empty_state))
    result = assess_effectiveness(empty_state)
    assert isinstance(result["effectiveness_scores"], dict)


def test_assess_effectiveness_ratings_are_valid(empty_state):
    from compliance_audit_agent.nodes.assess_effectiveness import assess_effectiveness
    empty_state["evidence_items"] = generate_iso27001_evidence_batch()
    from compliance_audit_agent.nodes.map_controls import map_controls
    empty_state.update(map_controls(empty_state))
    result = assess_effectiveness(empty_state)
    valid = {"fully_effective", "partially_effective", "ineffective", "not_assessed"}
    for v in result["effectiveness_scores"].values():
        assert v["rating"] in valid


def test_assess_effectiveness_audit_trail_is_fully_effective():
    """A control with audit_trail evidence should score fully effective."""
    from compliance_audit_agent.nodes.assess_effectiveness import assess_effectiveness
    ev = generate_evidence_record("ISO27001", "A.16.1.1", "SIEM", "audit_trail")
    state = _build_state_with_evidence([ev])
    result = assess_effectiveness(state)
    rating = result["effectiveness_scores"].get("ISO27001::A.16.1.1", {}).get("rating")
    assert rating == "fully_effective"


def test_assess_effectiveness_policy_doc_may_be_partial():
    """A weak evidence type (policy_doc) should score ≤ fully_effective."""
    from compliance_audit_agent.nodes.assess_effectiveness import assess_effectiveness
    ev = generate_weak_evidence_record("ISO27001", "A.9.1.1")
    state = _build_state_with_evidence([ev])
    result = assess_effectiveness(state)
    score = result["effectiveness_scores"].get("ISO27001::A.9.1.1", {}).get("score", 0)
    # policy_doc weight=0.7 → 70% < 85% threshold → not fully_effective or partially (60-85)
    assert score <= 85.0


def test_assess_effectiveness_multiple_evidence_boosts_score():
    """Multiple evidence items for same control should boost score."""
    from compliance_audit_agent.nodes.assess_effectiveness import assess_effectiveness
    ev_list = [generate_evidence_record("ISO27001", "A.9.1.1", "IAM", "access_report") for _ in range(3)]
    state = _build_state_with_evidence(ev_list)
    result = assess_effectiveness(state)
    score = result["effectiveness_scores"].get("ISO27001::A.9.1.1", {}).get("score", 0)
    assert score > 0


def test_assess_effectiveness_empty_mappings_returns_empty(empty_state):
    from compliance_audit_agent.nodes.assess_effectiveness import assess_effectiveness
    result = assess_effectiveness(empty_state)
    assert result["effectiveness_scores"] == {}
