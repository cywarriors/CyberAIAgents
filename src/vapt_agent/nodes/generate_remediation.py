"""Node 7 – Generate Remediation recommendations.

Produces actionable fix guidance per finding.  Implements FR-10 from SRS-13.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_REMEDIATION_TEMPLATES: dict[str, str] = {
    "CWE-89": "Use parameterised queries / prepared statements. Apply input validation.",
    "CWE-79": "Encode output using context-aware encoding. Implement Content-Security-Policy.",
    "CWE-78": "Avoid OS command construction from user input. Use allow-list validation.",
    "CWE-94": "Disable dynamic code evaluation. Apply strict sandboxing.",
    "CWE-798": "Remove hard-coded credentials. Rotate secrets and use a vault service.",
    "CWE-521": "Enforce strong password policy. Implement MFA.",
}


def generate_remediation(state: dict[str, Any]) -> dict[str, Any]:
    """Generate remediation items for scored findings."""
    risk_scores = state.get("risk_scores", [])
    scan_results = state.get("scan_results", [])

    # Index scan results for CWE lookup
    finding_map: dict[str, dict] = {}
    for f in scan_results:
        finding_map[f.get("finding_id", "")] = f

    remediation_items: list[dict[str, Any]] = []
    for scored in risk_scores:
        fid = scored.get("finding_id", "")
        finding = finding_map.get(fid, {})
        cwe = finding.get("cwe_id", "")
        title = scored.get("title") or finding.get("title", "")

        guidance = _REMEDIATION_TEMPLATES.get(cwe, "")
        if not guidance:
            guidance = (
                f"Review and patch the vulnerability: {title}. "
                "Consult vendor advisories and apply the latest security update."
            )

        remediation_items.append({
            "remediation_id": str(uuid.uuid4()),
            "finding_id": fid,
            "asset_id": scored.get("asset_id", ""),
            "title": title,
            "severity": scored.get("severity", "info"),
            "composite_score": scored.get("composite_score", 0),
            "cwe_id": cwe,
            "cve_id": scored.get("cve_id"),
            "guidance": guidance,
            "priority": _priority_label(scored.get("composite_score", 0)),
        })

    logger.info(
        "remediation_generated",
        engagement_id=state.get("engagement_id"),
        count=len(remediation_items),
    )
    return {"remediation_items": remediation_items}


def _priority_label(score: float) -> str:
    if score >= 80:
        return "P1-Immediate"
    if score >= 60:
        return "P2-Urgent"
    if score >= 40:
        return "P3-Moderate"
    return "P4-Low"
