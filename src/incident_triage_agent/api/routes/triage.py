"""Triage metrics endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from incident_triage_agent.api.dependencies import get_store
from incident_triage_agent.api.schemas import TriageMetrics

router = APIRouter(prefix="/api/v1/triage", tags=["triage"])


@router.get("/metrics", response_model=TriageMetrics)
async def get_triage_metrics():
    store = get_store()
    incidents = list(store.incidents.values())
    feedback_items = list(store.feedback)

    total_triaged = len(incidents)

    category_distribution: dict[str, int] = {}
    for inc in incidents:
        cat = inc.get("classification", "unknown")
        category_distribution[cat] = category_distribution.get(cat, 0) + 1

    escalated = sum(1 for i in incidents if i.get("status") == "escalated")
    escalation_rate = round(escalated / total_triaged * 100, 1) if total_triaged else 0.0

    tp = sum(1 for f in feedback_items if f.get("verdict") == "true_positive")
    fp = sum(1 for f in feedback_items if f.get("verdict") == "false_positive")
    total_verdicts = tp + fp
    tp_rate = round(tp / total_verdicts * 100, 1) if total_verdicts else 0.0
    fp_rate = round(fp / total_verdicts * 100, 1) if total_verdicts else 0.0

    return TriageMetrics(
        total_triaged=total_triaged,
        mttt_trend=[],
        priority_accuracy=100.0,
        escalation_rate=escalation_rate,
        true_positive_rate=tp_rate,
        false_positive_rate=fp_rate,
        category_distribution=category_distribution,
    )
