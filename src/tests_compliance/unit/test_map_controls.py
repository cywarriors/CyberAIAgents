"""Unit tests for map_controls node."""

from tests_compliance.mocks.generators import (
    generate_iso27001_evidence_batch,
    generate_mixed_evidence_batch,
)


def test_map_controls_creates_mappings(empty_state):
    from compliance_audit_agent.nodes.map_controls import map_controls
    empty_state["evidence_items"] = generate_iso27001_evidence_batch()
    result = map_controls(empty_state)
    assert len(result["control_mappings"]) > 0


def test_map_controls_each_mapping_has_required_fields(empty_state):
    from compliance_audit_agent.nodes.map_controls import map_controls
    empty_state["evidence_items"] = generate_iso27001_evidence_batch()
    result = map_controls(empty_state)
    for m in result["control_mappings"]:
        assert "mapping_id" in m
        assert "control_id" in m
        assert "framework" in m
        assert "evidence_ids" in m


def test_map_controls_deduplicates_per_framework_control(empty_state):
    """Two evidence items for same control → one mapping entry."""
    from compliance_audit_agent.nodes.map_controls import map_controls
    from tests_compliance.mocks.generators import generate_evidence_record
    ev1 = generate_evidence_record("ISO27001", "A.9.1.1", "IAM", "access_report")
    ev2 = generate_evidence_record("ISO27001", "A.9.1.1", "SIEM", "log_summary")
    empty_state["evidence_items"] = [ev1, ev2]
    result = map_controls(empty_state)
    assert len(result["control_mappings"]) == 1
    assert len(result["control_mappings"][0]["evidence_ids"]) == 2


def test_map_controls_cross_framework_harmonisation(empty_state):
    from compliance_audit_agent.nodes.map_controls import map_controls
    from tests_compliance.mocks.generators import generate_evidence_record
    # A.9.1.1 harmonises to NIST_CSF::PR.AC-1, SOC2::CC6.1, PCI_DSS::8.3
    ev = generate_evidence_record("ISO27001", "A.9.1.1")
    empty_state["evidence_items"] = [ev]
    result = map_controls(empty_state)
    assert len(result["control_mappings"][0]["cross_framework_ids"]) > 0


def test_map_controls_returns_list(empty_state):
    from compliance_audit_agent.nodes.map_controls import map_controls
    result = map_controls(empty_state)
    assert isinstance(result["control_mappings"], list)


def test_map_controls_empty_evidence_gives_empty_mappings(empty_state):
    from compliance_audit_agent.nodes.map_controls import map_controls
    result = map_controls(empty_state)
    assert result["control_mappings"] == []
