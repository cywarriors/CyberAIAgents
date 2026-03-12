"""Unit tests for the VAPT rules engine and baseline rules."""

from __future__ import annotations

import pytest
from vapt_agent.rules.engine import VulnRulesEngine
from vapt_agent.rules.vuln_rules import (
    BASELINE_RULES,
    critical_cvss,
    known_exploited,
    high_epss,
    default_credentials,
    sql_injection,
    xss_detected,
    rce_detected,
    outdated_ssl_tls,
)


class TestVulnRulesEngine:
    def test_add_and_evaluate(self):
        engine = VulnRulesEngine()
        engine.add("TEST-01", lambda f: {"match": True} if f.get("test") else None)

        result = engine.evaluate({"test": True})
        assert len(result) == 1
        assert result[0]["rule_id"] == "TEST-01"

        result = engine.evaluate({"test": False})
        assert len(result) == 0

    def test_disable_rule(self):
        engine = VulnRulesEngine()
        engine.add("TEST-01", lambda f: {"match": True})

        engine.disable("TEST-01")
        assert engine.evaluate({"anything": 1}) == []

        engine.enable("TEST-01")
        assert len(engine.evaluate({"anything": 1})) == 1

    def test_exception_handling(self):
        engine = VulnRulesEngine()
        engine.add("BAD", lambda f: 1 / 0)
        # Should not raise, should return empty
        result = engine.evaluate({})
        assert result == []


class TestBaselineRules:
    def test_critical_cvss_match(self):
        assert critical_cvss({"cvss_score": 9.5}) is not None
        assert critical_cvss({"cvss_score": 8.9}) is None

    def test_known_exploited(self):
        assert known_exploited({"in_kev": True}) is not None
        assert known_exploited({"in_kev": False}) is None

    def test_high_epss(self):
        assert high_epss({"epss_score": 0.8}) is not None
        assert high_epss({"epss_score": 0.3}) is None

    def test_default_credentials_cwe(self):
        assert default_credentials({"cwe_id": "CWE-798"}) is not None
        assert default_credentials({"cwe_id": "CWE-521"}) is not None
        assert default_credentials({"title": "Default credential found"}) is not None
        assert default_credentials({"cwe_id": "CWE-79"}) is None

    def test_sql_injection(self):
        assert sql_injection({"cwe_id": "CWE-89"}) is not None
        assert sql_injection({"title": "SQL Injection in form"}) is not None
        assert sql_injection({"cwe_id": "CWE-79"}) is None

    def test_xss_detected(self):
        assert xss_detected({"cwe_id": "CWE-79"}) is not None
        assert xss_detected({"title": "Cross-Site Scripting found"}) is not None
        assert xss_detected({"title": "XSS in param"}) is not None
        assert xss_detected({"cwe_id": "CWE-89"}) is None

    def test_rce_detected(self):
        assert rce_detected({"cwe_id": "CWE-94"}) is not None
        assert rce_detected({"cwe_id": "CWE-78"}) is not None
        assert rce_detected({"title": "Remote Code Execution"}) is not None
        assert rce_detected({"title": "XSS"}) is None

    def test_outdated_ssl(self):
        assert outdated_ssl_tls({"title": "SSLv3 enabled"}) is not None
        assert outdated_ssl_tls({"title": "TLSv1.0 detected"}) is not None
        assert outdated_ssl_tls({"title": "Weak cipher suite"}) is not None
        assert outdated_ssl_tls({"title": "TLSv1.3 configured"}) is None

    def test_all_rules_registered(self):
        assert len(BASELINE_RULES) == 8
        engine = VulnRulesEngine()
        for rule_id, fn in BASELINE_RULES.items():
            engine.add(rule_id, fn)
        # High-severity finding should hit multiple rules
        result = engine.evaluate({
            "cvss_score": 10.0,
            "in_kev": True,
            "epss_score": 0.9,
            "cwe_id": "CWE-89",
            "title": "SQL Injection",
        })
        rule_ids = {r["rule_id"] for r in result}
        assert "VULN-001" in rule_ids  # critical CVSS
        assert "VULN-002" in rule_ids  # KEV
        assert "VULN-003" in rule_ids  # high EPSS
        assert "VULN-005" in rule_ids  # SQL injection
