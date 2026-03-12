"""Tuning workbench metrics endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from threat_detection_agent.api.dependencies import get_store
from threat_detection_agent.api.schemas import TuningMetrics

router = APIRouter(prefix="/api/v1/tuning", tags=["tuning"])


@router.get("/metrics", response_model=TuningMetrics)
async def get_tuning_metrics():
    store = get_store()
    feedback = store.feedback
    total = len(feedback)
    tp = sum(1 for f in feedback if f.get("verdict") == "true_positive")
    fp = sum(1 for f in feedback if f.get("verdict") == "false_positive")
    nt = sum(1 for f in feedback if f.get("verdict") == "needs_tuning")

    # Rule hit rates
    rule_hits: list[dict] = []
    for rule in store.rules.values():
        rule_hits.append(
            {
                "rule_id": rule["rule_id"],
                "rule_name": rule["rule_name"],
                "hit_count": rule.get("hit_count", 0),
                "status": rule.get("status", "draft"),
            }
        )
    rule_hits.sort(key=lambda r: r["hit_count"], reverse=True)

    return TuningMetrics(
        total_feedback=total,
        true_positive_rate=round(tp / total, 3) if total else 0.0,
        false_positive_rate=round(fp / total, 3) if total else 0.0,
        needs_tuning_count=nt,
        rule_hit_rates=rule_hits[:10],
        threshold_recommendations=[],
    )
