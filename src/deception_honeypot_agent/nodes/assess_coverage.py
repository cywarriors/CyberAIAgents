"""AssessCoverageNode — evaluate deception coverage and recommend placements."""
from __future__ import annotations
import structlog

log = structlog.get_logger()

# Target: at least one decoy per segment type
_TARGET_DECOY_TYPES = {"fake_server", "honey_db", "fake_share", "fake_api", "honey_account"}


def _s(state, key, default):
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def assess_coverage(state) -> dict:
    """Evaluate current deception coverage and produce gap recommendations."""
    from deception_honeypot_agent.config import get_settings
    s = get_settings()

    decoys = list(_s(state, "decoy_inventory", []))
    active_decoys = [d for d in decoys if d.get("active", True)]

    deployed_types = {d.get("decoy_type", "") for d in active_decoys}
    missing_types = _TARGET_DECOY_TYPES - deployed_types
    coverage_pct = (len(deployed_types) / len(_TARGET_DECOY_TYPES)) * 100 if _TARGET_DECOY_TYPES else 100.0

    recommendations = []
    for dt in missing_types:
        recommendations.append({
            "decoy_type": dt,
            "reason": f"No {dt} decoys deployed in current inventory",
            "priority": "high",
        })

    assessment = {
        "total_decoys": len(decoys),
        "active_decoys": len(active_decoys),
        "deployed_types": list(deployed_types),
        "missing_types": list(missing_types),
        "coverage_percent": round(coverage_pct, 1),
        "target_percent": s.coverage_target_percent,
        "meets_target": coverage_pct >= s.coverage_target_percent,
        "recommendations": recommendations,
    }

    log.info("assess_coverage.done", coverage_pct=coverage_pct, missing=len(missing_types))
    return {"coverage_assessment": assessment}
