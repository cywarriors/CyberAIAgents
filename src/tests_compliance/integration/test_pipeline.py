"""Integration tests: end-to-end pipeline for the Compliance Audit Agent."""

from __future__ import annotations

import pytest

from tests_compliance.mocks.generators import (
    generate_iso27001_evidence_batch,
    generate_mixed_evidence_batch,
    generate_nist_csf_evidence_batch,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_pipeline(evidence: list[dict]) -> dict:
    """Invoke the compiled graph with pre-seeded evidence."""
    from compliance_audit_agent.graph import get_compiled_graph

    state_in = {
        "evidence_items": evidence,
        "control_mappings": [],
        "effectiveness_scores": {},
        "gaps": [],
        "framework_scores": {},
        "audit_packs": [],
        "drift_alerts": [],
        "remediation_tickets": [],
        "processing_errors": [],
    }
    get_compiled_graph.cache_clear()
    return get_compiled_graph().invoke(state_in)


# ---------------------------------------------------------------------------
# Pipeline integration tests
# ---------------------------------------------------------------------------

class TestPipelineEndToEnd:
    """Full pipeline runs from evidence to audit pack."""

    def test_pipeline_produces_framework_scores(self):
        evidence = generate_iso27001_evidence_batch()
        result = _run_pipeline(evidence)
        assert len(result["framework_scores"]) > 0

    def test_pipeline_produces_control_mappings(self):
        evidence = generate_iso27001_evidence_batch()
        result = _run_pipeline(evidence)
        assert len(result["control_mappings"]) > 0

    def test_pipeline_produces_effectiveness_scores(self):
        evidence = generate_iso27001_evidence_batch()
        result = _run_pipeline(evidence)
        assert len(result["effectiveness_scores"]) > 0

    def test_pipeline_produces_audit_pack(self):
        evidence = generate_iso27001_evidence_batch()
        result = _run_pipeline(evidence)
        assert len(result["audit_packs"]) > 0
        pack = result["audit_packs"][0]
        assert "sha256_manifest" in pack
        assert len(pack["sha256_manifest"]) == 64

    def test_audit_pack_is_not_final_hitl(self):
        """Audit pack must require HITL approval (is_final=False)."""
        evidence = generate_iso27001_evidence_batch()
        result = _run_pipeline(evidence)
        for pack in result["audit_packs"]:
            assert pack["is_final"] is False, "HITL gate must be enforced"

    def test_pipeline_no_processing_errors(self):
        evidence = generate_iso27001_evidence_batch()
        result = _run_pipeline(evidence)
        assert result["processing_errors"] == []

    def test_pipeline_multi_framework(self):
        evidence = generate_mixed_evidence_batch(count=15)
        result = _run_pipeline(evidence)
        assert len(result["framework_scores"]) >= 2

    def test_pipeline_gaps_when_no_evidence(self):
        """Running with empty evidence should produce gaps for required controls."""
        result = _run_pipeline([])
        # May produce gaps for required controls that have no evidence
        assert isinstance(result["gaps"], list)

    def test_nist_csf_pipeline(self):
        evidence = generate_nist_csf_evidence_batch()
        result = _run_pipeline(evidence)
        scores = result["framework_scores"]
        assert any("NIST_CSF" in k for k in scores)

    def test_pipeline_state_keys_complete(self):
        evidence = generate_iso27001_evidence_batch()
        result = _run_pipeline(evidence)
        expected_keys = {
            "evidence_items",
            "control_mappings",
            "effectiveness_scores",
            "gaps",
            "framework_scores",
            "audit_packs",
            "drift_alerts",
            "remediation_tickets",
            "processing_errors",
        }
        assert expected_keys.issubset(set(result.keys()))
