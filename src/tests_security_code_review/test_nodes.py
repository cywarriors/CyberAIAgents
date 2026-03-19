"""Unit tests for SRS-11 nodes."""
from __future__ import annotations
import pytest
from tests_security_code_review.mocks import (
    make_scan_target, make_vulnerable_diff_lines, make_clean_diff_lines,
    make_secret_diff_lines, make_sast_finding, make_secrets_finding, make_sca_finding,
    make_dependencies,
)


# ---------------------------------------------------------------------------
# IngestCode
# ---------------------------------------------------------------------------
class TestIngestCode:
    def test_ingest_passthrough_target(self, empty_state):
        from security_code_review_agent.nodes.ingest_code import ingest_code
        target = make_scan_target(repo="org/myapp")
        state = {**empty_state, "scan_target": target}
        result = ingest_code(state)
        assert result["scan_target"]["repo"] == "org/myapp"

    def test_ingest_empty_diff_lines(self, empty_state):
        from security_code_review_agent.nodes.ingest_code import ingest_code
        result = ingest_code({**empty_state, "scan_target": make_scan_target()})
        assert isinstance(result["scan_target"].get("diff_lines", []), list)

    def test_ingest_preserves_pr_number(self, empty_state):
        from security_code_review_agent.nodes.ingest_code import ingest_code
        target = make_scan_target()
        target["pr_number"] = 99
        result = ingest_code({**empty_state, "scan_target": target})
        assert result["scan_target"].get("pr_number") == 99


# ---------------------------------------------------------------------------
# SASTScan
# ---------------------------------------------------------------------------
class TestSASTScan:
    def test_sast_detects_sql_injection(self, empty_state):
        from security_code_review_agent.nodes.sast_scan import sast_scan
        target = make_scan_target(diff_lines=make_vulnerable_diff_lines())
        result = sast_scan({**empty_state, "scan_target": target})
        ids = [f["rule_id"] for f in result["sast_findings"]]
        assert any("sql" in r.lower() for r in ids)

    def test_sast_detects_hardcoded_secret(self, empty_state):
        from security_code_review_agent.nodes.sast_scan import sast_scan
        target = make_scan_target(diff_lines=make_vulnerable_diff_lines())
        result = sast_scan({**empty_state, "scan_target": target})
        assert any(f["severity"] in ("critical", "high") for f in result["sast_findings"])

    def test_sast_clean_code_no_findings(self, empty_state):
        from security_code_review_agent.nodes.sast_scan import sast_scan
        target = make_scan_target(diff_lines=make_clean_diff_lines())
        result = sast_scan({**empty_state, "scan_target": target})
        assert result["sast_findings"] == []

    def test_sast_empty_diff_no_findings(self, empty_state):
        from security_code_review_agent.nodes.sast_scan import sast_scan
        result = sast_scan({**empty_state, "scan_target": make_scan_target()})
        assert result["sast_findings"] == []

    def test_sast_snippet_length_capped(self, empty_state):
        from security_code_review_agent.nodes.sast_scan import sast_scan
        long_line = "password = '" + "x" * 200 + "'"
        target = make_scan_target(diff_lines=[{"content": long_line, "file": "f.py", "line": 1}])
        result = sast_scan({**empty_state, "scan_target": target})
        for f in result["sast_findings"]:
            assert len(f.get("code_snippet", "")) <= 105  # 100 + "..."

    def test_sast_finding_has_cwe(self, empty_state):
        from security_code_review_agent.nodes.sast_scan import sast_scan
        target = make_scan_target(diff_lines=make_vulnerable_diff_lines())
        result = sast_scan({**empty_state, "scan_target": target})
        for f in result["sast_findings"]:
            assert "cwe_id" in f


# ---------------------------------------------------------------------------
# DetectSecrets
# ---------------------------------------------------------------------------
class TestDetectSecrets:
    def test_detects_api_key(self, empty_state):
        from security_code_review_agent.nodes.detect_secrets import detect_secrets
        target = make_scan_target(diff_lines=make_secret_diff_lines())
        result = detect_secrets({**empty_state, "scan_target": target})
        assert len(result["secrets_findings"]) > 0

    def test_secret_value_always_redacted(self, empty_state):
        from security_code_review_agent.nodes.detect_secrets import detect_secrets
        target = make_scan_target(diff_lines=make_secret_diff_lines())
        result = detect_secrets({**empty_state, "scan_target": target})
        for f in result["secrets_findings"]:
            assert f["redacted_value"] == "[REDACTED]"
            # Actual secret must not appear
            assert "AKIA" not in str(f.get("redacted_value", ""))

    def test_no_secrets_clean_code(self, empty_state):
        from security_code_review_agent.nodes.detect_secrets import detect_secrets
        target = make_scan_target(diff_lines=make_clean_diff_lines())
        result = detect_secrets({**empty_state, "scan_target": target})
        assert result["secrets_findings"] == []

    def test_secrets_severity_is_critical(self, empty_state):
        from security_code_review_agent.nodes.detect_secrets import detect_secrets
        target = make_scan_target(diff_lines=make_secret_diff_lines())
        result = detect_secrets({**empty_state, "scan_target": target})
        for f in result["secrets_findings"]:
            assert f["severity"] == "critical"

    def test_secrets_finding_has_file_and_line(self, empty_state):
        from security_code_review_agent.nodes.detect_secrets import detect_secrets
        target = make_scan_target(diff_lines=make_secret_diff_lines())
        result = detect_secrets({**empty_state, "scan_target": target})
        for f in result["secrets_findings"]:
            assert "file_path" in f
            assert "line_number" in f


# ---------------------------------------------------------------------------
# SCAScan
# ---------------------------------------------------------------------------
class TestSCAScan:
    def test_sca_no_vulns_without_db_url(self, empty_state):
        from security_code_review_agent.nodes.sca_scan import sca_scan
        target = make_scan_target(dependencies=make_dependencies())
        result = sca_scan({**empty_state, "scan_target": target})
        # Without NVD URL configured, result should still be a list
        assert isinstance(result["sca_findings"], list)

    def test_sca_empty_deps(self, empty_state):
        from security_code_review_agent.nodes.sca_scan import sca_scan
        result = sca_scan({**empty_state, "scan_target": make_scan_target(dependencies=[])})
        assert result["sca_findings"] == []


# ---------------------------------------------------------------------------
# GenerateFixes
# ---------------------------------------------------------------------------
class TestGenerateFixes:
    def test_fix_for_sql_injection(self, empty_state):
        from security_code_review_agent.nodes.generate_fixes import generate_fixes
        finding = make_sast_finding(rule_id="sql_injection")
        result = generate_fixes({**empty_state, "sast_findings": [finding]})
        assert len(result["fix_suggestions"]) > 0
        fix = result["fix_suggestions"][0]
        assert "description" in fix or "guidance" in fix or "code_example" in fix

    def test_fix_for_secret_finding(self, empty_state):
        from security_code_review_agent.nodes.generate_fixes import generate_fixes
        secret = make_secrets_finding()
        result = generate_fixes({**empty_state, "secrets_findings": [secret]})
        assert len(result["fix_suggestions"]) > 0

    def test_fix_references_finding_id(self, empty_state):
        from security_code_review_agent.nodes.generate_fixes import generate_fixes
        finding = make_sast_finding(rule_id="xss")
        result = generate_fixes({**empty_state, "sast_findings": [finding]})
        fix_ids = [f.get("finding_id") for f in result["fix_suggestions"]]
        assert finding["finding_id"] in fix_ids

    def test_no_findings_no_fixes(self, empty_state):
        from security_code_review_agent.nodes.generate_fixes import generate_fixes
        result = generate_fixes(empty_state)
        assert result["fix_suggestions"] == []

    def test_fix_has_guidance(self, empty_state):
        from security_code_review_agent.nodes.generate_fixes import generate_fixes
        finding = make_sast_finding(rule_id="hardcoded_secret")
        result = generate_fixes({**empty_state, "sast_findings": [finding]})
        for fix in result["fix_suggestions"]:
            text = fix.get("description", fix.get("guidance", fix.get("code_example", "")))
            assert len(text) > 0


# ---------------------------------------------------------------------------
# EvaluatePolicy
# ---------------------------------------------------------------------------
class TestEvaluatePolicy:
    def test_critical_finding_blocks(self, empty_state):
        from security_code_review_agent.nodes.evaluate_policy import evaluate_policy
        finding = make_sast_finding(severity="critical")
        result = evaluate_policy({**empty_state, "sast_findings": [finding]})
        assert result["policy_verdict"]["verdict"] == "block"

    def test_high_severity_warns(self, empty_state):
        from security_code_review_agent.nodes.evaluate_policy import evaluate_policy
        finding = make_sast_finding(severity="high")
        result = evaluate_policy({**empty_state, "sast_findings": [finding]})
        assert result["policy_verdict"]["verdict"] in ("warn", "block")

    def test_low_severity_passes(self, empty_state):
        from security_code_review_agent.nodes.evaluate_policy import evaluate_policy
        finding = make_sast_finding(severity="low")
        result = evaluate_policy({**empty_state, "sast_findings": [finding]})
        assert result["policy_verdict"]["verdict"] == "pass"

    def test_no_findings_passes(self, empty_state):
        from security_code_review_agent.nodes.evaluate_policy import evaluate_policy
        result = evaluate_policy(empty_state)
        assert result["policy_verdict"]["verdict"] == "pass"

    def test_block_requires_appsec_approval(self, empty_state):
        from security_code_review_agent.nodes.evaluate_policy import evaluate_policy
        finding = make_sast_finding(severity="critical")
        result = evaluate_policy({**empty_state, "sast_findings": [finding]})
        assert result["policy_verdict"]["requires_appsec_approval"] is True

    def test_secret_finding_blocks(self, empty_state):
        from security_code_review_agent.nodes.evaluate_policy import evaluate_policy
        secret = make_secrets_finding()  # severity=critical
        result = evaluate_policy({**empty_state, "secrets_findings": [secret]})
        assert result["policy_verdict"]["verdict"] == "block"


# ---------------------------------------------------------------------------
# GenerateSBOM
# ---------------------------------------------------------------------------
class TestGenerateSBOM:
    def test_sbom_has_components(self, empty_state):
        from security_code_review_agent.nodes.generate_sbom import generate_sbom
        target = make_scan_target(dependencies=make_dependencies(3))
        result = generate_sbom({**empty_state, "scan_target": target})
        assert len(result["sbom"]["components"]) == 3

    def test_sbom_format_is_cyclonedx(self, empty_state):
        from security_code_review_agent.nodes.generate_sbom import generate_sbom
        result = generate_sbom({**empty_state, "scan_target": make_scan_target()})
        assert result["sbom"]["format"] == "cyclonedx"

    def test_sbom_empty_deps(self, empty_state):
        from security_code_review_agent.nodes.generate_sbom import generate_sbom
        result = generate_sbom({**empty_state, "scan_target": make_scan_target(dependencies=[])})
        assert result["sbom"]["components"] == []

    def test_sbom_has_id(self, empty_state):
        from security_code_review_agent.nodes.generate_sbom import generate_sbom
        result = generate_sbom({**empty_state, "scan_target": make_scan_target()})
        assert len(result["sbom"]["sbom_id"]) == 36  # UUID

    def test_sbom_component_has_purl(self, empty_state):
        from security_code_review_agent.nodes.generate_sbom import generate_sbom
        target = make_scan_target(dependencies=make_dependencies(2))
        result = generate_sbom({**empty_state, "scan_target": target})
        for comp in result["sbom"]["components"]:
            assert "purl" in comp

    def test_sbom_vuln_linked_to_component(self, empty_state):
        from security_code_review_agent.nodes.generate_sbom import generate_sbom
        sca = make_sca_finding()
        sca["package_name"] = "requests"
        target = make_scan_target(dependencies=[{"name": "requests", "version": "2.28.0"}])
        result = generate_sbom({**empty_state, "scan_target": target, "sca_findings": [sca]})
        comp = next((c for c in result["sbom"]["components"] if c["name"] == "requests"), None)
        assert comp is not None
        assert len(comp["vulnerabilities"]) > 0


# ---------------------------------------------------------------------------
# TrackLifecycle
# ---------------------------------------------------------------------------
class TestTrackLifecycle:
    def test_lifecycle_acknowledges_findings(self, empty_state):
        from security_code_review_agent.nodes.track_lifecycle import track_lifecycle
        finding = make_sast_finding()
        result = track_lifecycle({**empty_state, "sast_findings": [finding]})
        assert isinstance(result["lifecycle_updates"], list)
        assert len(result["lifecycle_updates"]) > 0

    def test_lifecycle_empty_state(self, empty_state):
        from security_code_review_agent.nodes.track_lifecycle import track_lifecycle
        result = track_lifecycle(empty_state)
        assert isinstance(result["lifecycle_updates"], list)

    def test_lifecycle_update_has_finding_id(self, empty_state):
        from security_code_review_agent.nodes.track_lifecycle import track_lifecycle
        finding = make_sast_finding()
        result = track_lifecycle({**empty_state, "sast_findings": [finding]})
        ids = [u.get("finding_id") for u in result["lifecycle_updates"]]
        assert finding["finding_id"] in ids


# ---------------------------------------------------------------------------
# SAST Rules engine
# ---------------------------------------------------------------------------
class TestSASTRulesEngine:
    def test_engine_returns_list(self):
        from security_code_review_agent.rules.sast_rules import SASTRulesEngine
        engine = SASTRulesEngine()
        result = engine.scan(make_scan_target())
        assert isinstance(result, list)

    def test_engine_detects_patterns(self):
        from security_code_review_agent.rules.sast_rules import SASTRulesEngine
        engine = SASTRulesEngine()
        target = make_scan_target(diff_lines=make_vulnerable_diff_lines())
        result = engine.scan(target)
        assert len(result) > 0

    def test_engine_owasp_category_present(self):
        from security_code_review_agent.rules.sast_rules import SASTRulesEngine
        engine = SASTRulesEngine()
        target = make_scan_target(diff_lines=make_vulnerable_diff_lines())
        result = engine.scan(target)
        for f in result:
            assert "owasp_category" in f
