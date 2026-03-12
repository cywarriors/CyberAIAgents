"""Node 6 – Score and Prioritise findings.

Composite risk scoring: CVSS 30 %, EPSS 20 %, Exploitability 25 %,
Asset Criticality 15 %, Exposure 10 %.  Implements FR-09 from SRS-13.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from vapt_agent.config import get_settings

logger = structlog.get_logger(__name__)

_CRITICALITY_SCORE = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.0,
}


def score_and_prioritize(state: dict[str, Any]) -> dict[str, Any]:
    """Compute composite risk score for each scan finding."""
    settings = get_settings()
    scan_results = state.get("scan_results", [])
    exploits = state.get("validated_exploits", [])
    assets = state.get("discovered_assets", [])

    # Index helpers
    exploit_by_finding: dict[str, dict] = {}
    for e in exploits:
        exploit_by_finding[e.get("finding_id", "")] = e

    asset_by_id: dict[str, dict] = {a["asset_id"]: a for a in assets}

    scored: list[dict[str, Any]] = []
    for finding in scan_results:
        fid = finding.get("finding_id", "")
        asset_id = finding.get("asset_id", "")
        asset = asset_by_id.get(asset_id, {})
        exploit = exploit_by_finding.get(fid, {})

        # Component scores (normalised 0-1)
        cvss_norm = min((finding.get("cvss_score") or 0) / 10.0, 1.0)
        epss_norm = min(finding.get("epss_score") or 0, 1.0)
        exploit_norm = 1.0 if exploit.get("success") else 0.0
        crit_norm = _CRITICALITY_SCORE.get(
            asset.get("criticality", "medium"), 0.5
        )
        # Exposure: KEV membership or public-facing
        exposure_norm = 1.0 if finding.get("in_kev") else 0.3

        composite = (
            settings.weight_cvss * cvss_norm
            + settings.weight_epss * epss_norm
            + settings.weight_exploitability * exploit_norm
            + settings.weight_asset_criticality * crit_norm
            + settings.weight_exposure * exposure_norm
        ) * 100

        composite = round(min(composite, 100.0), 2)

        scored.append({
            "scored_finding_id": str(uuid.uuid4()),
            "finding_id": fid,
            "asset_id": asset_id,
            "composite_score": composite,
            "cvss_component": round(cvss_norm * 100, 2),
            "epss_component": round(epss_norm * 100, 2),
            "exploit_component": round(exploit_norm * 100, 2),
            "criticality_component": round(crit_norm * 100, 2),
            "exposure_component": round(exposure_norm * 100, 2),
            "severity": finding.get("severity", "info"),
            "title": finding.get("title", ""),
            "cve_id": finding.get("cve_id"),
        })

    # Sort by composite score descending
    scored.sort(key=lambda s: s["composite_score"], reverse=True)

    logger.info(
        "findings_scored",
        engagement_id=state.get("engagement_id"),
        count=len(scored),
        top_score=scored[0]["composite_score"] if scored else 0,
    )
    return {"risk_scores": scored}
