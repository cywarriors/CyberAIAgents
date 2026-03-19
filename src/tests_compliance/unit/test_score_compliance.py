"""Unit tests for score_compliance node."""


def _state_with_effectiveness(ratings: dict[str, str], framework: str = "ISO27001") -> dict:
    eff = {
        f"{framework}::{ctrl}": {"control_id": ctrl, "framework": framework, "rating": rating, "score": 80.0, "evidence_count": 1}
        for ctrl, rating in ratings.items()
    }
    return {
        "evidence_items": [], "control_mappings": [], "effectiveness_scores": eff,
        "gaps": [], "framework_scores": {}, "audit_packs": [],
        "drift_alerts": [], "remediation_tickets": [], "processing_errors": [],
    }


def test_score_compliance_returns_dict(empty_state):
    from compliance_audit_agent.nodes.score_compliance import score_compliance
    result = score_compliance(empty_state)
    assert isinstance(result["framework_scores"], dict)


def test_score_compliance_all_fully_effective_gives_100(empty_state):
    from compliance_audit_agent.nodes.score_compliance import score_compliance
    state = _state_with_effectiveness({"A.9.1.1": "fully_effective", "A.12.4.1": "fully_effective"})
    result = score_compliance(state)
    score = result["framework_scores"]["ISO27001"]["score"]
    assert score == 100.0


def test_score_compliance_all_ineffective_gives_0():
    from compliance_audit_agent.nodes.score_compliance import score_compliance
    state = _state_with_effectiveness({"A.9.1.1": "ineffective", "A.12.4.1": "ineffective"})
    result = score_compliance(state)
    score = result["framework_scores"]["ISO27001"]["score"]
    assert score == 0.0


def test_score_compliance_mixed_ratings_between_0_and_100():
    from compliance_audit_agent.nodes.score_compliance import score_compliance
    state = _state_with_effectiveness({"A.9.1.1": "fully_effective", "A.12.4.1": "partially_effective", "A.16.1.1": "ineffective"})
    result = score_compliance(state)
    score = result["framework_scores"]["ISO27001"]["score"]
    assert 0.0 < score < 100.0


def test_score_compliance_counts_per_rating():
    from compliance_audit_agent.nodes.score_compliance import score_compliance
    state = _state_with_effectiveness({
        "A.5.1.1": "fully_effective",
        "A.9.1.1": "partially_effective",
        "A.12.4.1": "ineffective",
    })
    result = score_compliance(state)
    fw = result["framework_scores"]["ISO27001"]
    assert fw["controls_fully_effective"] == 1
    assert fw["controls_partially_effective"] == 1
    assert fw["controls_ineffective"] == 1


def test_score_compliance_no_evidence_gives_zero_score(empty_state):
    from compliance_audit_agent.nodes.score_compliance import score_compliance
    result = score_compliance(empty_state)
    for v in result["framework_scores"].values():
        assert v["score"] == 0.0


def test_score_compliance_framework_entry_has_required_fields():
    from compliance_audit_agent.nodes.score_compliance import score_compliance
    state = _state_with_effectiveness({"A.9.1.1": "fully_effective"})
    result = score_compliance(state)
    fw = result["framework_scores"]["ISO27001"]
    for field in ("framework", "score", "controls_assessed", "org_unit"):
        assert field in fw
