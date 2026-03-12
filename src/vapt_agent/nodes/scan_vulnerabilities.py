"""Node 3 – Scan Vulnerabilities.

Multi-engine vulnerability scanning with NVD/EPSS/KEV enrichment.
Implements FR-03, FR-04, FR-05 from SRS-13.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from vapt_agent.integrations.nvd_enrichment import enrich_cve
from vapt_agent.integrations.scanners import (
    run_nuclei_scan,
    run_nessus_scan,
    run_zap_scan,
)
from vapt_agent.rules.engine import VulnRulesEngine
from vapt_agent.rules.vuln_rules import BASELINE_RULES

logger = structlog.get_logger(__name__)

_engine = VulnRulesEngine()
for rule_id, fn in BASELINE_RULES.items():
    _engine.add(rule_id, fn)


def scan_vulnerabilities(state: dict[str, Any]) -> dict[str, Any]:
    """Run vulnerability scans across all discovered assets."""
    if not state.get("roe_validated"):
        return {
            "errors": [{
                "node": "scan_vulnerabilities",
                "message": "Skipped – RoE not validated.",
                "ts": datetime.now(timezone.utc).isoformat(),
            }]
        }

    assets = state.get("discovered_assets", [])
    if not assets:
        return {
            "errors": [{
                "node": "scan_vulnerabilities",
                "message": "No discovered assets to scan.",
                "ts": datetime.now(timezone.utc).isoformat(),
            }]
        }

    ips = [a["ip"] for a in assets if a.get("ip")]
    domains = [a["hostname"] for a in assets if a.get("hostname")]

    # Run scanners
    nuclei_findings = run_nuclei_scan(ips + domains)
    nessus_findings = run_nessus_scan(ips)

    # ZAP for web targets
    zap_findings: list[dict[str, Any]] = []
    for domain in domains:
        zap_findings.extend(run_zap_scan(f"https://{domain}"))

    # Merge all findings
    raw_findings = []
    for f in nuclei_findings + nessus_findings + zap_findings:
        finding: dict[str, Any] = {
            "finding_id": str(uuid.uuid4()),
            "asset_id": f.get("asset_id", ""),
            "scanner": f.get("scanner", "unknown"),
            "cve_id": f.get("cve_id"),
            "cwe_id": f.get("cwe_id"),
            "title": f.get("title", ""),
            "severity": f.get("severity", "info"),
            "cvss_score": f.get("cvss_score"),
            "raw": f,
        }

        # Enrich from NVD/EPSS/KEV
        if finding["cve_id"]:
            enrichment = enrich_cve(finding["cve_id"])
            finding["cvss_score"] = enrichment.get("cvss_score", finding["cvss_score"])
            finding["epss_score"] = enrichment.get("epss_score")
            finding["in_kev"] = enrichment.get("in_kev", False)

        # Evaluate rules
        rule_matches = _engine.evaluate(finding)
        if rule_matches:
            # Take highest severity from rule matches
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            best = max(rule_matches, key=lambda m: sev_order.get(m.get("severity", "info"), 0))
            finding["severity"] = best["severity"]
            finding["matched_rules"] = [m["rule_id"] for m in rule_matches]

        raw_findings.append(finding)

    logger.info(
        "scan_complete",
        engagement_id=state.get("engagement_id"),
        findings_count=len(raw_findings),
    )
    return {"scan_results": raw_findings}
