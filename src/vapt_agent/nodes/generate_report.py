"""Node 8 – Generate Report artifacts.

Produces executive, technical, and compliance report artifacts.
Implements FR-10 from SRS-13.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from vapt_agent.config import get_settings

logger = structlog.get_logger(__name__)


def generate_report(state: dict[str, Any]) -> dict[str, Any]:
    """Generate report artifacts from scored findings and remediation items."""
    settings = get_settings()
    engagement_id = state.get("engagement_id", "unknown")
    risk_scores = state.get("risk_scores", [])
    remediation_items = state.get("remediation_items", [])
    attack_paths = state.get("attack_paths", [])
    discovered_assets = state.get("discovered_assets", [])
    validated_exploits = state.get("validated_exploits", [])

    ts = datetime.now(timezone.utc).isoformat()

    # Executive summary
    total = len(risk_scores)
    critical = sum(1 for r in risk_scores if r.get("severity") == "critical")
    high = sum(1 for r in risk_scores if r.get("severity") == "high")
    medium = sum(1 for r in risk_scores if r.get("severity") == "medium")
    low = sum(1 for r in risk_scores if r.get("severity") in ("low", "info"))

    executive_summary = {
        "report_type": "executive",
        "engagement_id": engagement_id,
        "generated_at": ts,
        "total_findings": total,
        "severity_breakdown": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low_info": low,
        },
        "assets_tested": len(discovered_assets),
        "attack_paths_found": len(attack_paths),
        "exploits_validated": sum(1 for e in validated_exploits if e.get("success")),
        "top_findings": risk_scores[:5],
    }

    # Technical report
    technical_report = {
        "report_type": "technical",
        "engagement_id": engagement_id,
        "generated_at": ts,
        "findings": risk_scores,
        "remediation_items": remediation_items,
        "attack_paths": attack_paths,
        "discovered_assets": discovered_assets,
        "validated_exploits": validated_exploits,
    }

    # Compliance report (OWASP Top-10 mapping)
    compliance_report = {
        "report_type": "compliance",
        "engagement_id": engagement_id,
        "generated_at": ts,
        "framework": "OWASP Top 10 - 2021",
        "findings_by_category": _map_owasp(risk_scores),
    }

    artifacts: list[dict[str, Any]] = []
    for report, rtype in [
        (executive_summary, "executive"),
        (technical_report, "technical"),
        (compliance_report, "compliance"),
    ]:
        artifact_id = str(uuid.uuid4())
        artifacts.append({
            "artifact_id": artifact_id,
            "report_type": rtype,
            "engagement_id": engagement_id,
            "generated_at": ts,
            "content": report,
        })

        # Persist to disk if output dir is configured
        out_dir = Path(settings.report_output_dir)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            fname = out_dir / f"{engagement_id}_{rtype}_{artifact_id[:8]}.json"
            fname.write_text(json.dumps(report, indent=2, default=str))
            logger.info("report_written", path=str(fname))
        except OSError:
            logger.warning("report_write_failed", report_type=rtype)

    logger.info(
        "reports_generated",
        engagement_id=engagement_id,
        count=len(artifacts),
    )
    return {"report_artifacts": artifacts}


def _map_owasp(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Map CWE IDs to OWASP Top-10 2021 categories."""
    owasp_map: dict[str, list[str]] = {
        "A01:2021 – Broken Access Control": ["CWE-22", "CWE-284", "CWE-285"],
        "A02:2021 – Cryptographic Failures": ["CWE-327", "CWE-328", "CWE-330"],
        "A03:2021 – Injection": ["CWE-89", "CWE-79", "CWE-78", "CWE-94"],
        "A04:2021 – Insecure Design": ["CWE-209", "CWE-256"],
        "A05:2021 – Security Misconfiguration": ["CWE-16", "CWE-611"],
        "A06:2021 – Vulnerable Components": [],
        "A07:2021 – Auth Failures": ["CWE-798", "CWE-521", "CWE-287"],
        "A08:2021 – Integrity Failures": ["CWE-502", "CWE-829"],
        "A09:2021 – Logging Failures": ["CWE-778"],
        "A10:2021 – SSRF": ["CWE-918"],
    }
    counts: dict[str, int] = {cat: 0 for cat in owasp_map}
    cwe_to_cat = {}
    for cat, cwes in owasp_map.items():
        for cwe in cwes:
            cwe_to_cat[cwe] = cat

    for f in findings:
        cwe = f.get("cwe_id", "")
        cat = cwe_to_cat.get(cwe)
        if cat:
            counts[cat] += 1
    return counts
