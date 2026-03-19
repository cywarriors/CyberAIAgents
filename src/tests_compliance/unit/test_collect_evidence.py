"""Unit tests for collect_evidence node."""

from tests_compliance.mocks.generators import (
    generate_evidence_record,
    generate_mixed_evidence_batch,
)


def test_collect_evidence_passes_through_preseeded(empty_state):
    from compliance_audit_agent.nodes.collect_evidence import collect_evidence
    pre = generate_mixed_evidence_batch(5)
    empty_state["evidence_items"] = pre
    result = collect_evidence(empty_state)
    assert len(result["evidence_items"]) >= 5


def test_collect_evidence_returns_list(empty_state):
    from compliance_audit_agent.nodes.collect_evidence import collect_evidence
    result = collect_evidence(empty_state)
    assert isinstance(result["evidence_items"], list)


def test_collect_evidence_no_api_keys_returns_empty_or_preloaded(empty_state):
    from compliance_audit_agent.nodes.collect_evidence import collect_evidence
    result = collect_evidence(empty_state)
    # With no API URLs configured, collected should be empty
    assert result["evidence_items"] == []


def test_collect_evidence_each_item_has_required_fields(empty_state):
    from compliance_audit_agent.nodes.collect_evidence import collect_evidence
    ev = generate_evidence_record()
    empty_state["evidence_items"] = [ev]
    result = collect_evidence(empty_state)
    for item in result["evidence_items"]:
        assert "evidence_id" in item
        assert "source_system" in item
        assert "framework" in item
        assert "control_id" in item


def test_collect_evidence_preserves_sha256_hash(empty_state):
    from compliance_audit_agent.nodes.collect_evidence import collect_evidence
    ev = generate_evidence_record()
    empty_state["evidence_items"] = [ev]
    result = collect_evidence(empty_state)
    assert result["evidence_items"][0]["sha256_hash"] != ""


def test_collect_evidence_accepts_multi_framework_input(empty_state):
    from compliance_audit_agent.nodes.collect_evidence import collect_evidence
    items = [
        generate_evidence_record("ISO27001"),
        generate_evidence_record("NIST_CSF"),
        generate_evidence_record("SOC2"),
    ]
    empty_state["evidence_items"] = items
    result = collect_evidence(empty_state)
    frameworks = {ev["framework"] for ev in result["evidence_items"]}
    assert len(frameworks) == 3
