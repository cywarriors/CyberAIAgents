"""VAPT attack scenarios for integration / detection tests.

Each scenario describes an expected engagement outcome so integration tests
can assert the pipeline produces the right findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VAPTScenario:
    """A test scenario for VAPT engagement validation."""

    name: str
    description: str
    roe: dict[str, Any]
    injected_assets: list[dict[str, Any]]
    injected_findings: list[dict[str, Any]]
    expected_min_critical: int = 0
    expected_min_high: int = 0
    expected_min_findings: int = 0
    expected_rule_ids: list[str] = field(default_factory=list)


SCENARIOS: list[VAPTScenario] = [
    VAPTScenario(
        name="sql_injection_attack",
        description="Web application with critical SQL injection",
        roe={
            "roe_id": "roe-sqli-01",
            "scope_ips": ["10.0.1.10"],
            "scope_domains": ["app.example.com"],
            "allow_destructive": False,
        },
        injected_assets=[{
            "asset_id": "asset-web-01",
            "ip": "10.0.1.10",
            "hostname": "app.example.com",
            "os_fingerprint": "Ubuntu 22.04",
            "open_ports": [80, 443],
            "services": [{"port": 443, "service": "https"}],
            "asset_type": "server",
            "criticality": "critical",
        }],
        injected_findings=[{
            "finding_id": "find-sqli-01",
            "asset_id": "asset-web-01",
            "title": "SQL Injection in login form",
            "cve_id": "CVE-2023-12345",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "cvss_score": 9.8,
            "epss_score": 0.85,
            "in_kev": True,
            "scanner": "nuclei",
        }],
        expected_min_critical=1,
        expected_min_findings=1,
        expected_rule_ids=["VULN-001", "VULN-002", "VULN-003", "VULN-005"],
    ),
    VAPTScenario(
        name="rce_with_lateral_movement",
        description="RCE vulnerability enabling lateral movement",
        roe={
            "roe_id": "roe-rce-01",
            "scope_ips": ["10.0.1.10", "10.0.1.11"],
            "scope_domains": ["api.example.com"],
            "allow_destructive": True,
        },
        injected_assets=[
            {
                "asset_id": "asset-api-01",
                "ip": "10.0.1.10",
                "hostname": "api.example.com",
                "os_fingerprint": "CentOS 8",
                "open_ports": [8080],
                "services": [{"port": 8080, "service": "http-proxy"}],
                "asset_type": "server",
                "criticality": "critical",
            },
            {
                "asset_id": "asset-db-01",
                "ip": "10.0.1.11",
                "hostname": "db.example.com",
                "os_fingerprint": "Ubuntu 22.04",
                "open_ports": [5432],
                "services": [{"port": 5432, "service": "postgresql"}],
                "asset_type": "server",
                "criticality": "critical",
            },
        ],
        injected_findings=[
            {
                "finding_id": "find-rce-01",
                "asset_id": "asset-api-01",
                "title": "Remote Code Execution via deserialization",
                "cve_id": "CVE-2023-44100",
                "cwe_id": "CWE-94",
                "severity": "critical",
                "cvss_score": 10.0,
                "epss_score": 0.92,
                "in_kev": True,
                "scanner": "nuclei",
            },
            {
                "finding_id": "find-defcred-01",
                "asset_id": "asset-db-01",
                "title": "Default credentials on database",
                "cve_id": None,
                "cwe_id": "CWE-798",
                "severity": "critical",
                "cvss_score": 9.0,
                "epss_score": 0.88,
                "in_kev": False,
                "scanner": "nessus",
            },
        ],
        expected_min_critical=2,
        expected_min_findings=2,
        expected_rule_ids=["VULN-001", "VULN-002", "VULN-004", "VULN-007"],
    ),
    VAPTScenario(
        name="xss_medium_risk",
        description="Cross-site scripting on a non-critical asset",
        roe={
            "roe_id": "roe-xss-01",
            "scope_ips": ["10.0.2.20"],
            "scope_domains": ["blog.example.com"],
            "allow_destructive": False,
        },
        injected_assets=[{
            "asset_id": "asset-blog-01",
            "ip": "10.0.2.20",
            "hostname": "blog.example.com",
            "os_fingerprint": "Alpine 3.18",
            "open_ports": [443],
            "services": [{"port": 443, "service": "https"}],
            "asset_type": "container",
            "criticality": "low",
        }],
        injected_findings=[{
            "finding_id": "find-xss-01",
            "asset_id": "asset-blog-01",
            "title": "Cross-Site Scripting (XSS) in search",
            "cve_id": "CVE-2023-12346",
            "cwe_id": "CWE-79",
            "severity": "high",
            "cvss_score": 7.5,
            "epss_score": 0.45,
            "in_kev": False,
            "scanner": "zap",
        }],
        expected_min_high=1,
        expected_min_findings=1,
        expected_rule_ids=["VULN-006"],
    ),
    VAPTScenario(
        name="info_only_clean_scan",
        description="Clean environment with only informational findings",
        roe={
            "roe_id": "roe-clean-01",
            "scope_ips": ["10.0.3.30"],
            "scope_domains": ["secure.example.com"],
            "allow_destructive": False,
        },
        injected_assets=[{
            "asset_id": "asset-sec-01",
            "ip": "10.0.3.30",
            "hostname": "secure.example.com",
            "os_fingerprint": "Ubuntu 22.04",
            "open_ports": [443],
            "services": [{"port": 443, "service": "https"}],
            "asset_type": "server",
            "criticality": "medium",
        }],
        injected_findings=[{
            "finding_id": "find-info-01",
            "asset_id": "asset-sec-01",
            "title": "Information disclosure via server banner",
            "cve_id": None,
            "cwe_id": None,
            "severity": "info",
            "cvss_score": 0.0,
            "epss_score": 0.01,
            "in_kev": False,
            "scanner": "nuclei",
        }],
        expected_min_critical=0,
        expected_min_high=0,
        expected_min_findings=1,
        expected_rule_ids=[],
    ),
    VAPTScenario(
        name="deprecated_ssl_tls",
        description="Server using deprecated TLSv1.0 protocol",
        roe={
            "roe_id": "roe-ssl-01",
            "scope_ips": ["10.0.4.40"],
            "scope_domains": ["legacy.example.com"],
            "allow_destructive": False,
        },
        injected_assets=[{
            "asset_id": "asset-legacy-01",
            "ip": "10.0.4.40",
            "hostname": "legacy.example.com",
            "os_fingerprint": "Windows Server 2022",
            "open_ports": [443],
            "services": [{"port": 443, "service": "https"}],
            "asset_type": "server",
            "criticality": "medium",
        }],
        injected_findings=[{
            "finding_id": "find-ssl-01",
            "asset_id": "asset-legacy-01",
            "title": "TLSv1.0 detected on port 443",
            "cve_id": None,
            "cwe_id": None,
            "severity": "medium",
            "cvss_score": 5.3,
            "epss_score": 0.05,
            "in_kev": False,
            "scanner": "nessus",
        }],
        expected_min_critical=0,
        expected_min_high=0,
        expected_min_findings=1,
        expected_rule_ids=["VULN-008"],
    ),
]
