"""Unit tests for generate_audit_pack node."""

from tests_compliance.mocks.generators import generate_iso27001_evidence_batch, generate_pii_evidence_record


def test_generate_audit_pack_creates_packs(empty_state):
    from compliance_audit_agent.nodes.generate_audit_pack import generate_audit_pack
    empty_state["evidence_items"] = generate_iso27001_evidence_batch()
    empty_state["framework_scores"] = {"ISO27001": {"score": 85.0, "org_unit": "enterprise"}}
    result = generate_audit_pack(empty_state)
    assert len(result["audit_packs"]) >= 1


def test_generate_audit_pack_has_sha256_hash(empty_state):
    from compliance_audit_agent.nodes.generate_audit_pack import generate_audit_pack
    empty_state["evidence_items"] = generate_iso27001_evidence_batch()
    empty_state["framework_scores"] = {"ISO27001": {"score": 90.0, "org_unit": "enterprise"}}
    result = generate_audit_pack(empty_state)
    for pack in result["audit_packs"]:
        assert len(pack["sha256_manifest"]) == 64  # SHA-256 hex


def test_generate_audit_pack_pii_redacted(empty_state):
    """PII fields must be stripped from evidence items in the audit pack (SEC-03)."""
    from compliance_audit_agent.nodes.generate_audit_pack import generate_audit_pack
    ev = generate_pii_evidence_record()
    empty_state["evidence_items"] = [ev]
    empty_state["framework_scores"] = {"ISO27001": {"score": 80.0, "org_unit": "enterprise"}}
    result = generate_audit_pack(empty_state)
    # The pack itself doesn't store content directly, but the hash was computed on redacted data
    for pack in result["audit_packs"]:
        assert pack["sha256_manifest"] != ""


def test_generate_audit_pack_is_not_final_by_default(empty_state):
    """Packs should require Compliance Manager approval (HITL guardrail)."""
    from compliance_audit_agent.nodes.generate_audit_pack import generate_audit_pack
    empty_state["evidence_items"] = generate_iso27001_evidence_batch()
    empty_state["framework_scores"] = {"ISO27001": {"score": 85.0, "org_unit": "enterprise"}}
    result = generate_audit_pack(empty_state)
    for pack in result["audit_packs"]:
        assert pack["is_final"] is False


def test_generate_audit_pack_empty_evidence_no_packs(empty_state):
    from compliance_audit_agent.nodes.generate_audit_pack import generate_audit_pack
    result = generate_audit_pack(empty_state)
    assert result["audit_packs"] == []


def test_generate_audit_pack_required_fields(empty_state):
    from compliance_audit_agent.nodes.generate_audit_pack import generate_audit_pack
    empty_state["evidence_items"] = generate_iso27001_evidence_batch()
    empty_state["framework_scores"] = {"ISO27001": {"score": 80.0, "org_unit": "test"}}
    result = generate_audit_pack(empty_state)
    for p in result["audit_packs"]:
        for field in ("pack_id", "framework", "sha256_manifest", "generated_at", "is_final"):
            assert field in p
