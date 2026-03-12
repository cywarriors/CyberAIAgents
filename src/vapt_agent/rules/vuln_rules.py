"""Baseline vulnerability rules mapped to CWE / OWASP categories."""

from __future__ import annotations

from typing import Any


def critical_cvss(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Flag findings with CVSS >= 9.0."""
    score = finding.get("cvss_score") or 0
    if score >= 9.0:
        return {
            "rule_id": "VULN-001",
            "title": "Critical CVSS score",
            "severity": "critical",
            "cvss_score": score,
        }
    return None


def known_exploited(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Flag findings on the CISA KEV catalogue."""
    if finding.get("in_kev"):
        return {
            "rule_id": "VULN-002",
            "title": "Known Exploited Vulnerability (KEV)",
            "severity": "critical",
        }
    return None


def high_epss(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Flag findings with EPSS probability > 0.7."""
    epss = finding.get("epss_score") or 0
    if epss > 0.7:
        return {
            "rule_id": "VULN-003",
            "title": "High exploitation probability (EPSS)",
            "severity": "high",
            "epss_score": epss,
        }
    return None


def default_credentials(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Flag default / weak credential findings (CWE-798, CWE-521)."""
    cwe = finding.get("cwe_id", "")
    title_lower = (finding.get("title") or "").lower()
    if cwe in ("CWE-798", "CWE-521") or "default credential" in title_lower:
        return {
            "rule_id": "VULN-004",
            "title": "Default or weak credentials",
            "severity": "critical",
        }
    return None


def sql_injection(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Flag SQL injection findings (CWE-89)."""
    cwe = finding.get("cwe_id", "")
    title_lower = (finding.get("title") or "").lower()
    if cwe == "CWE-89" or "sql injection" in title_lower:
        return {
            "rule_id": "VULN-005",
            "title": "SQL Injection",
            "severity": "critical",
        }
    return None


def xss_detected(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Flag Cross-Site Scripting findings (CWE-79)."""
    cwe = finding.get("cwe_id", "")
    title_lower = (finding.get("title") or "").lower()
    if cwe == "CWE-79" or "cross-site scripting" in title_lower or "xss" in title_lower:
        return {
            "rule_id": "VULN-006",
            "title": "Cross-Site Scripting (XSS)",
            "severity": "high",
        }
    return None


def rce_detected(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Flag Remote Code Execution findings (CWE-94, CWE-78)."""
    cwe = finding.get("cwe_id", "")
    title_lower = (finding.get("title") or "").lower()
    if cwe in ("CWE-94", "CWE-78") or "remote code execution" in title_lower:
        return {
            "rule_id": "VULN-007",
            "title": "Remote Code Execution",
            "severity": "critical",
        }
    return None


def outdated_ssl_tls(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Flag deprecated SSL/TLS protocol usage."""
    title_lower = (finding.get("title") or "").lower()
    if any(kw in title_lower for kw in ("sslv3", "tlsv1.0", "tlsv1.1", "weak cipher")):
        return {
            "rule_id": "VULN-008",
            "title": "Deprecated SSL/TLS protocol",
            "severity": "medium",
        }
    return None


BASELINE_RULES: dict[str, Any] = {
    "VULN-001": critical_cvss,
    "VULN-002": known_exploited,
    "VULN-003": high_epss,
    "VULN-004": default_credentials,
    "VULN-005": sql_injection,
    "VULN-006": xss_detected,
    "VULN-007": rce_detected,
    "VULN-008": outdated_ssl_tls,
}
