"""IdentifyGapsNode – find missing controls and insufficient evidence."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from compliance_audit_agent.config import get_settings
from compliance_audit_agent.rules.control_catalog import ControlCatalog

log = structlog.get_logger()

_CATALOG = ControlCatalog()


_REMEDIATION_GUIDANCE: dict[str, str] = {
    "no_evidence": "Collect evidence from the relevant source system and re-run assessment.",
    "insufficient_evidence": "Gather additional evidence items to improve control coverage score.",
    "ineffective": "Review control implementation and address identified weaknesses. Consult control owner for remediation plan.",
    "partially_effective": "Address gaps in control implementation to achieve full effectiveness rating.",
}


def _s(state: Any, key: str, default: Any) -> Any:
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def identify_gaps(state: Any) -> dict[str, Any]:
    """FR-04: Identify control gaps and missing evidence per framework."""
    s = get_settings()
    effectiveness_scores = _s(state, "effectiveness_scores", {})
    control_mappings = _s(state, "control_mappings", [])
    enabled_frameworks = [f.strip() for f in s.enabled_frameworks.split(",")]

    gaps: list[dict[str, Any]] = []

    # Check mapped controls for ineffective or partially effective assessments
    for ctrl_key, eff in effectiveness_scores.items():
        rating = eff.get("rating", "not_assessed")
        if rating in ("ineffective", "partially_effective", "not_assessed"):
            gap_type = "ineffective" if rating == "ineffective" else (
                "partially_effective" if rating == "partially_effective" else "no_evidence"
            )
            severity = "critical" if rating == "ineffective" else "high"
            gaps.append({
                "gap_id": str(uuid.uuid4()),
                "control_id": eff["control_id"],
                "framework": eff["framework"],
                "description": f"Control {eff['control_id']} rated as {rating} (score: {eff.get('score', 0):.1f}%)",
                "severity": severity,
                "remediation_guidance": _REMEDIATION_GUIDANCE.get(gap_type, "Review control implementation."),
                "ticket_id": None,
                "identified_at": __import__("datetime").datetime.utcnow().isoformat(),
            })

    # Check for controls in catalog that have no evidence at all
    mapped_ctrl_ids = {m["control_id"] for m in control_mappings}
    for framework in enabled_frameworks:
        for ctrl_id in _CATALOG.get_required_controls(framework):
            if ctrl_id not in mapped_ctrl_ids:
                gaps.append({
                    "gap_id": str(uuid.uuid4()),
                    "control_id": ctrl_id,
                    "framework": framework,
                    "description": f"No evidence collected for required control {ctrl_id}",
                    "severity": "high",
                    "remediation_guidance": _REMEDIATION_GUIDANCE["no_evidence"],
                    "ticket_id": None,
                    "identified_at": __import__("datetime").datetime.utcnow().isoformat(),
                })

    log.info("identify_gaps.done", gaps=len(gaps))
    return {"gaps": gaps}
