"""Node 5 – Analyze Attack Paths.

Chains validated exploits into lateral-movement attack paths.
Implements FR-08 from SRS-13.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def analyze_attack_paths(state: dict[str, Any]) -> dict[str, Any]:
    """Build attack-path chains from validated exploits and scan findings."""
    exploits = state.get("validated_exploits", [])
    scan_results = state.get("scan_results", [])
    assets = state.get("discovered_assets", [])

    # Index findings by asset_id
    finding_by_id: dict[str, dict] = {f["finding_id"]: f for f in scan_results}
    asset_by_id: dict[str, dict] = {a["asset_id"]: a for a in assets}

    # Group successful exploits by asset
    asset_exploits: dict[str, list[dict]] = defaultdict(list)
    for exp in exploits:
        if not exp.get("success"):
            continue
        finding = finding_by_id.get(exp.get("finding_id", ""), {})
        asset_id = finding.get("asset_id", "unknown")
        asset_exploits[asset_id].append({**exp, **finding})

    # Build simple linear chains (asset A -> asset B via lateral movement)
    paths: list[dict[str, Any]] = []
    asset_ids = list(asset_exploits.keys())

    for i, src_id in enumerate(asset_ids):
        steps: list[dict[str, Any]] = []
        step_num = 1
        for exploit_info in asset_exploits[src_id]:
            steps.append({
                "step": step_num,
                "asset_id": src_id,
                "technique": exploit_info.get("cve_id") or exploit_info.get("title", "unknown"),
                "mitre_technique_id": exploit_info.get("mitre_technique_id"),
            })
            step_num += 1

        # Check for potential pivot to next asset
        if i + 1 < len(asset_ids):
            next_id = asset_ids[i + 1]
            if asset_exploits[next_id]:
                for exploit_info in asset_exploits[next_id]:
                    steps.append({
                        "step": step_num,
                        "asset_id": next_id,
                        "technique": exploit_info.get("cve_id") or exploit_info.get("title", "unknown"),
                        "mitre_technique_id": exploit_info.get("mitre_technique_id"),
                    })
                    step_num += 1

        if steps:
            # Composite risk = max CVSS of all findings in the path
            max_cvss = 0.0
            for s in steps:
                for exp_info in asset_exploits.get(s["asset_id"], []):
                    score = exp_info.get("cvss_score") or 0
                    if score > max_cvss:
                        max_cvss = score

            paths.append({
                "path_id": str(uuid.uuid4()),
                "steps": steps,
                "composite_risk": round(max_cvss, 1),
                "asset_count": len({s["asset_id"] for s in steps}),
            })

    logger.info(
        "attack_paths_analysed",
        engagement_id=state.get("engagement_id"),
        path_count=len(paths),
    )
    return {"attack_paths": paths}
