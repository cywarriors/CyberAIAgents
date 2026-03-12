"""Deterministic mock data generators for the VAPT agent tests.

Mirrors the pattern from threat_detection_agent tests/mocks/generators.py –
uses a seeded RNG for reproducibility and provides helpers that produce
realistic VAPT engagement payloads.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

_RNG = random.Random(42)


def _uid() -> str:
    return str(uuid.UUID(int=_RNG.getrandbits(128), version=4))


# ---------------------------------------------------------------------------
# RoE helpers
# ---------------------------------------------------------------------------

def generate_valid_roe(
    *,
    scope_ips: list[str] | None = None,
    scope_domains: list[str] | None = None,
    allow_destructive: bool = False,
) -> dict[str, Any]:
    """Generate a valid Rules of Engagement record."""
    now = datetime.now(timezone.utc)
    return {
        "roe_id": _uid(),
        "scope_ips": scope_ips or ["10.0.1.10", "10.0.1.11", "10.0.1.12"],
        "scope_domains": scope_domains or ["app.example.com", "api.example.com"],
        "scope_cloud_accounts": [],
        "exclusions": ["10.0.1.255"],
        "allow_destructive": allow_destructive,
        "start_time": now.isoformat(),
        "end_time": (now + timedelta(hours=8)).isoformat(),
    }


def generate_expired_roe() -> dict[str, Any]:
    """Generate an RoE whose time window has passed."""
    past = datetime.now(timezone.utc) - timedelta(days=2)
    roe = generate_valid_roe()
    roe["start_time"] = (past - timedelta(hours=8)).isoformat()
    roe["end_time"] = past.isoformat()
    return roe


def generate_incomplete_roe() -> dict[str, Any]:
    """Generate an RoE missing required fields."""
    return {"roe_id": _uid()}


# ---------------------------------------------------------------------------
# Asset helpers
# ---------------------------------------------------------------------------

_OS_OPTIONS = ["Ubuntu 22.04", "Windows Server 2022", "CentOS 8", "Alpine 3.18"]
_SERVICES = [
    {"port": 22, "service": "ssh", "version": "OpenSSH 8.9"},
    {"port": 80, "service": "http", "version": "nginx 1.24"},
    {"port": 443, "service": "https", "version": "nginx 1.24"},
    {"port": 3306, "service": "mysql", "version": "MySQL 8.0"},
    {"port": 5432, "service": "postgresql", "version": "PostgreSQL 15"},
    {"port": 8080, "service": "http-proxy", "version": "Apache Tomcat 9"},
]


def generate_discovered_assets(count: int = 3) -> list[dict[str, Any]]:
    """Generate a list of discovered asset dicts."""
    assets = []
    for i in range(count):
        ip = f"10.0.1.{10 + i}"
        svc_count = _RNG.randint(1, 4)
        services = _RNG.sample(_SERVICES, min(svc_count, len(_SERVICES)))
        assets.append({
            "asset_id": _uid(),
            "ip": ip,
            "hostname": f"host-{i}.example.com",
            "os_fingerprint": _RNG.choice(_OS_OPTIONS),
            "open_ports": [s["port"] for s in services],
            "services": services,
            "asset_type": _RNG.choice(["server", "workstation", "container"]),
            "criticality": _RNG.choice(["critical", "high", "medium", "low"]),
            "cloud_provider": None,
        })
    return assets


# ---------------------------------------------------------------------------
# Scan finding helpers
# ---------------------------------------------------------------------------

_VULN_TEMPLATES = [
    {
        "title": "SQL Injection in login form",
        "cve_id": "CVE-2023-12345",
        "cwe_id": "CWE-89",
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.85,
        "in_kev": True,
        "scanner": "nuclei",
    },
    {
        "title": "Cross-Site Scripting (XSS) in search",
        "cve_id": "CVE-2023-12346",
        "cwe_id": "CWE-79",
        "severity": "high",
        "cvss_score": 7.5,
        "epss_score": 0.45,
        "in_kev": False,
        "scanner": "zap",
    },
    {
        "title": "Default credentials on admin panel",
        "cve_id": None,
        "cwe_id": "CWE-798",
        "severity": "critical",
        "cvss_score": 9.0,
        "epss_score": 0.90,
        "in_kev": False,
        "scanner": "nessus",
    },
    {
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
        "title": "Outdated TLSv1.0 protocol",
        "cve_id": None,
        "cwe_id": None,
        "severity": "medium",
        "cvss_score": 5.3,
        "epss_score": 0.05,
        "in_kev": False,
        "scanner": "nessus",
    },
    {
        "title": "Information disclosure via server banner",
        "cve_id": None,
        "cwe_id": None,
        "severity": "info",
        "cvss_score": 0.0,
        "epss_score": 0.01,
        "in_kev": False,
        "scanner": "nuclei",
    },
    {
        "title": "OS Command Injection in file upload",
        "cve_id": "CVE-2023-55001",
        "cwe_id": "CWE-78",
        "severity": "critical",
        "cvss_score": 9.5,
        "epss_score": 0.78,
        "in_kev": True,
        "scanner": "zap",
    },
    {
        "title": "Weak SSH cipher suite",
        "cve_id": None,
        "cwe_id": None,
        "severity": "low",
        "cvss_score": 3.1,
        "epss_score": 0.02,
        "in_kev": False,
        "scanner": "nessus",
    },
]


def generate_scan_findings(
    assets: list[dict[str, Any]],
    count: int | None = None,
) -> list[dict[str, Any]]:
    """Generate scan findings distributed across the given assets."""
    if count is None:
        count = len(_VULN_TEMPLATES)
    findings = []
    for i in range(count):
        template = _VULN_TEMPLATES[i % len(_VULN_TEMPLATES)]
        asset = assets[i % len(assets)]
        findings.append({
            "finding_id": _uid(),
            "asset_id": asset["asset_id"],
            **template,
        })
    return findings


def generate_benign_findings(assets: list[dict[str, Any]], count: int = 3) -> list[dict[str, Any]]:
    """Generate low-severity / informational findings only."""
    findings = []
    for i in range(count):
        asset = assets[i % len(assets)]
        findings.append({
            "finding_id": _uid(),
            "asset_id": asset["asset_id"],
            "title": f"Info finding {i}",
            "cve_id": None,
            "cwe_id": None,
            "severity": "info",
            "cvss_score": 0.0,
            "epss_score": 0.01,
            "in_kev": False,
            "scanner": "nessus",
        })
    return findings


# ---------------------------------------------------------------------------
# Full engagement state builder
# ---------------------------------------------------------------------------

def build_engagement_state(
    *,
    roe: dict[str, Any] | None = None,
    asset_count: int = 3,
    finding_count: int | None = None,
    include_exploits: bool = True,
) -> dict[str, Any]:
    """Build a complete engagement state dict ready for pipeline invocation."""
    if roe is None:
        roe = generate_valid_roe()
    assets = generate_discovered_assets(asset_count)
    findings = generate_scan_findings(assets, finding_count)

    exploits = []
    if include_exploits:
        for f in findings:
            exploits.append({
                "exploit_id": _uid(),
                "finding_id": f["finding_id"],
                "module_name": "stub/safe-check",
                "risk_level": "safe",
                "success": f["severity"] in ("critical", "high"),
                "rollback_success": True,
            })

    return {
        "engagement_id": _uid(),
        "roe_authorization": roe,
        "roe_validated": True,
        "discovered_assets": assets,
        "scan_results": findings,
        "validated_exploits": exploits,
        "attack_paths": [],
        "risk_scores": [],
        "remediation_items": [],
        "report_artifacts": [],
        "published_findings": [],
        "errors": [],
    }
