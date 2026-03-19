"""Unit tests for identify_gaps node."""

from tests_compliance.mocks.generators import generate_iso27001_evidence_batch


def test_identify_gaps_returns_list(empty_state):
    from compliance_audit_agent.nodes.identify_gaps import identify_gaps
    result = identify_gaps(empty_state)
    assert isinstance(result["gaps"], list)


def test_identify_gaps_finds_missing_controls(empty_state):
    """With no evidence mapped, all required controls should be flagged as gaps."""
    from compliance_audit_agent.nodes.identify_gaps import identify_gaps
    result = identify_gaps(empty_state)
    # ISO27001 requires 6 controls, NIST_CSF 5, SOC2 3 → should have many gaps
    assert len(result["gaps"]) > 0


def test_identify_gaps_has_required_fields(empty_state):
    from compliance_audit_agent.nodes.identify_gaps import identify_gaps
    result = identify_gaps(empty_state)
    for g in result["gaps"]:
        assert "gap_id" in g
        assert "control_id" in g
        assert "framework" in g
        assert "severity" in g
        assert "remediation_guidance" in g


def test_identify_gaps_severity_values_valid(empty_state):
    from compliance_audit_agent.nodes.identify_gaps import identify_gaps
    result = identify_gaps(empty_state)
    valid = {"critical", "high", "medium", "low"}
    for g in result["gaps"]:
        assert g["severity"] in valid


def test_identify_gaps_ineffective_control_creates_gap():
    """An ineffective effectiveness score should generate a gap."""
    from compliance_audit_agent.nodes.identify_gaps import identify_gaps
    state = {
        "evidence_items": [],
        "control_mappings": [{"mapping_id": "m1", "control_id": "A.9.1.1", "framework": "ISO27001", "evidence_ids": ["e1"], "cross_framework_ids": []}],
        "effectiveness_scores": {"ISO27001::A.9.1.1": {"control_id": "A.9.1.1", "framework": "ISO27001", "rating": "ineffective", "score": 20.0, "evidence_count": 1}},
        "gaps": [], "framework_scores": {}, "audit_packs": [],
        "drift_alerts": [], "remediation_tickets": [], "processing_errors": [],
    }
    result = identify_gaps(state)
    assert any(g["control_id"] == "A.9.1.1" for g in result["gaps"])


def test_identify_gaps_fully_effective_no_gap():
    """A fully effective control should not generate a gap."""
    from compliance_audit_agent.nodes.identify_gaps import identify_gaps
    # Populate all required ISO27001 controls as fully_effective
    required = ["A.5.1.1", "A.9.1.1", "A.12.4.1", "A.12.6.1", "A.16.1.1", "A.18.1.1"]
    eff = {f"ISO27001::{c}": {"control_id": c, "framework": "ISO27001", "rating": "fully_effective", "score": 95.0, "evidence_count": 2} for c in required}
    mappings = [{"mapping_id": f"m{i}", "control_id": c, "framework": "ISO27001", "evidence_ids": ["e1"], "cross_framework_ids": []} for i, c in enumerate(required)]
    state = {
        "evidence_items": [],
        "control_mappings": mappings,
        "effectiveness_scores": eff,
        "gaps": [], "framework_scores": {}, "audit_packs": [],
        "drift_alerts": [], "remediation_tickets": [], "processing_errors": [],
    }
    result = identify_gaps(state)
    # Should have no ISO27001 gaps
    iso_gaps = [g for g in result["gaps"] if g["framework"] == "ISO27001"]
    assert len(iso_gaps) == 0
