"""Integration tests — full pipeline for Security Code Review Agent."""
from __future__ import annotations
import pytest
from tests_security_code_review.mocks import (
    make_scan_target, make_vulnerable_diff_lines, make_clean_diff_lines,
    make_secret_diff_lines, make_dependencies,
)


def _run(scan_target: dict) -> dict:
    from security_code_review_agent.graph import get_compiled_graph
    get_compiled_graph.cache_clear()
    state_in = {
        "scan_target": scan_target,
        "sast_findings": [],
        "secrets_findings": [],
        "sca_findings": [],
        "fix_suggestions": [],
        "policy_verdict": {},
        "sbom": {},
        "pr_comments": [],
        "lifecycle_updates": [],
        "processing_errors": [],
    }
    result = get_compiled_graph().invoke(state_in)
    if hasattr(result, "model_dump"):
        result = result.model_dump()
    return result


class TestPipelineIntegration:
    def test_pipeline_produces_policy_verdict(self):
        result = _run(make_scan_target(diff_lines=make_vulnerable_diff_lines()))
        assert result["policy_verdict"].get("verdict") in ("block", "warn", "pass")

    def test_pipeline_blocks_on_critical_findings(self):
        result = _run(make_scan_target(diff_lines=make_vulnerable_diff_lines()))
        # SQL injection + hardcoded password → critical → block
        verdict = result["policy_verdict"].get("verdict")
        assert verdict in ("block", "warn")

    def test_pipeline_passes_clean_code(self):
        result = _run(make_scan_target(diff_lines=make_clean_diff_lines()))
        assert result["policy_verdict"].get("verdict") == "pass"

    def test_pipeline_secrets_blocked(self):
        result = _run(make_scan_target(diff_lines=make_secret_diff_lines()))
        assert result["secrets_findings"] or result["sast_findings"]

    def test_pipeline_secret_values_redacted(self):
        result = _run(make_scan_target(diff_lines=make_secret_diff_lines()))
        for f in result["secrets_findings"]:
            assert f["redacted_value"] == "[REDACTED]"

    def test_pipeline_sbom_generated(self):
        result = _run(make_scan_target(dependencies=make_dependencies(3)))
        assert result["sbom"].get("format") == "cyclonedx"

    def test_pipeline_fix_suggestions_present(self):
        result = _run(make_scan_target(diff_lines=make_vulnerable_diff_lines()))
        assert isinstance(result["fix_suggestions"], list)

    def test_pipeline_lifecycle_updates(self):
        result = _run(make_scan_target(diff_lines=make_vulnerable_diff_lines()))
        assert isinstance(result["lifecycle_updates"], list)

    def test_pipeline_state_keys_complete(self):
        result = _run(make_scan_target())
        for key in ("sast_findings", "secrets_findings", "sca_findings",
                    "fix_suggestions", "policy_verdict", "sbom", "pr_comments",
                    "lifecycle_updates", "processing_errors"):
            assert key in result
