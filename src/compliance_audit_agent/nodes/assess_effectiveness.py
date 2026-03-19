"""AssessEffectivenessNode – evaluate control effectiveness from evidence."""

from __future__ import annotations

from typing import Any

import structlog

from compliance_audit_agent.config import get_settings
from compliance_audit_agent.rules.effectiveness_engine import EffectivenessEngine

log = structlog.get_logger()

_ENGINE = EffectivenessEngine()


def _s(state: Any, key: str, default: Any) -> Any:
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def assess_effectiveness(state: Any) -> dict[str, Any]:
    """FR-03: Assess control effectiveness as fully_effective / partially_effective / ineffective."""
    s = get_settings()
    control_mappings = _s(state, "control_mappings", [])
    evidence_items = _s(state, "evidence_items", [])

    # Build evidence lookup
    ev_index = {ev["evidence_id"]: ev for ev in evidence_items}

    effectiveness_scores: dict[str, Any] = {}

    for mapping in control_mappings:
        ctrl_key = f"{mapping['framework']}::{mapping['control_id']}"
        evidences = [ev_index[eid] for eid in mapping.get("evidence_ids", []) if eid in ev_index]

        rating, score = _ENGINE.evaluate(
            control_id=mapping["control_id"],
            framework=mapping["framework"],
            evidence_list=evidences,
            threshold_full=s.effectiveness_threshold_full,
            threshold_partial=s.effectiveness_threshold_partial,
        )
        effectiveness_scores[ctrl_key] = {
            "control_id": mapping["control_id"],
            "framework": mapping["framework"],
            "rating": rating,
            "score": score,
            "evidence_count": len(evidences),
        }

    log.info("assess_effectiveness.done", controls=len(effectiveness_scores))
    return {"effectiveness_scores": effectiveness_scores}
