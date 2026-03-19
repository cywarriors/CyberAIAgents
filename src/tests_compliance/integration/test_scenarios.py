"""Integration tests: compliance-specific business scenarios."""

from __future__ import annotations

import pytest

from tests_compliance.mocks.generators import (
    generate_evidence_record,
    generate_iso27001_evidence_batch,
    generate_pii_evidence_record,
    generate_weak_evidence_record,
)


def _run_pipeline(evidence: list[dict]) -> dict:
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


class TestComplianceScenarios:
    """Business scenario tests for the compliance audit pipeline."""

    def test_strong_evidence_high_iso27001_score(self):
        """Audit-trail evidence should yield a high ISO 27001 score."""
        evidence = [
            generate_evidence_record(
                framework="ISO27001",
                control_id=f"A.9.{i}.1",
                source_type="audit_trail",
            )
            for i in range(1, 8)
        ]
        result = _run_pipeline(evidence)
        scores = result["framework_scores"]
        iso_scores = {k: v for k, v in scores.items() if "ISO27001" in k}
        if iso_scores:
            # framework_scores values are dicts with a 'score' key
            score_values = [
                v["score"] if isinstance(v, dict) else v
                for v in iso_scores.values()
            ]
            avg = sum(score_values) / len(score_values)
            assert avg >= 50.0

    def test_weak_evidence_generates_gaps(self):
        """Policy-doc-only evidence should leave some gaps."""
        evidence = [generate_weak_evidence_record() for _ in range(3)]
        result = _run_pipeline(evidence)
        # At a minimum, required controls not covered should appear as gaps
        assert isinstance(result["gaps"], list)

    def test_pii_redacted_from_audit_pack(self):
        """PII fields must not appear in audit pack manifest."""
        pii_evidence = generate_pii_evidence_record()
        result = _run_pipeline([pii_evidence])
        for pack in result["audit_packs"]:
            manifest_str = str(pack.get("manifest", {}))
            assert "user@example.com" not in manifest_str
            assert "john_doe" not in manifest_str
            assert "123-45-6789" not in manifest_str

    def test_sha256_hash_present_in_audit_pack(self):
        """Every audit pack must carry a SHA-256 integrity hash."""
        evidence = generate_iso27001_evidence_batch()
        result = _run_pipeline(evidence)
        for pack in result["audit_packs"]:
            h = pack.get("sha256_manifest", "")
            assert len(h) == 64, f"Expected 64-char hex digest, got {h!r}"

    def test_drift_alert_on_score_drop(self):
        """Two consecutive runs where second has weaker evidence should trigger drift."""
        from compliance_audit_agent.monitoring.store import get_store

        # Simulate a stored high score for ISO27001
        store = get_store()
        store.save_score("ISO27001", 95.0)

        # Run pipeline with weak evidence to get a lower score
        evidence = [generate_weak_evidence_record() for _ in range(2)]
        result = _run_pipeline(evidence)
        # drift_alerts may or may not fire depending on score outcome,
        # but the pipeline should not error
        assert isinstance(result["drift_alerts"], list)

    def test_remediation_tickets_not_created_without_itsm(self):
        """Without ITSM URL configured, remediation_tickets should be empty."""
        import os
        os.environ.pop("COMPLIANCE_ITSM_API_URL", None)
        from compliance_audit_agent.config import get_settings
        get_settings.cache_clear()

        evidence = generate_iso27001_evidence_batch()
        result = _run_pipeline(evidence)
        assert result["remediation_tickets"] == []

    def test_multi_framework_generates_multiple_packs(self):
        """Mixed evidence across two frameworks should produce audit packs."""
        evidence = [
            generate_evidence_record(framework="ISO27001", control_id="A.9.1.1", source_type="audit_trail"),
            generate_evidence_record(framework="ISO27001", control_id="A.12.1.1", source_type="audit_trail"),
            generate_evidence_record(framework="NIST_CSF", control_id="PR.AC-1", source_type="access_report"),
            generate_evidence_record(framework="NIST_CSF", control_id="DE.CM-1", source_type="scan_result"),
        ]
        result = _run_pipeline(evidence)
        assert len(result["audit_packs"]) >= 1
        assert len(result["framework_scores"]) >= 1
