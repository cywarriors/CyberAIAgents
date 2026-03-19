"""ScoreComplianceNode – calculate posture scores per framework and org unit."""

from __future__ import annotations

from typing import Any

import structlog

from compliance_audit_agent.config import get_settings

log = structlog.get_logger()

_RATING_WEIGHTS = {
    "fully_effective": 1.0,
    "partially_effective": 0.5,
    "ineffective": 0.0,
    "not_assessed": 0.0,
}


def _s(state: Any, key: str, default: Any) -> Any:
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def score_compliance(state: Any) -> dict[str, Any]:
    """FR-07: Calculate compliance posture scores per framework."""
    s = get_settings()
    effectiveness_scores = _s(state, "effectiveness_scores", {})
    enabled_frameworks = [f.strip() for f in s.enabled_frameworks.split(",")]

    framework_scores: dict[str, Any] = {}

    for framework in enabled_frameworks:
        framework_evals = [
            v for v in effectiveness_scores.values()
            if v.get("framework") == framework
        ]

        if not framework_evals:
            framework_scores[framework] = {
                "framework": framework,
                "score": 0.0,
                "controls_assessed": 0,
                "controls_fully_effective": 0,
                "controls_partially_effective": 0,
                "controls_ineffective": 0,
                "org_unit": s.org_unit,
            }
            continue

        total_weight = sum(
            _RATING_WEIGHTS.get(ev.get("rating", "not_assessed"), 0.0)
            for ev in framework_evals
        )
        score = (total_weight / len(framework_evals)) * 100.0

        framework_scores[framework] = {
            "framework": framework,
            "score": round(score, 2),
            "controls_assessed": len(framework_evals),
            "controls_fully_effective": sum(1 for ev in framework_evals if ev.get("rating") == "fully_effective"),
            "controls_partially_effective": sum(1 for ev in framework_evals if ev.get("rating") == "partially_effective"),
            "controls_ineffective": sum(1 for ev in framework_evals if ev.get("rating") == "ineffective"),
            "org_unit": s.org_unit,
        }

    log.info("score_compliance.done", frameworks=list(framework_scores.keys()))
    return {"framework_scores": framework_scores}
