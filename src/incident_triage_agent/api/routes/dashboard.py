"""Dashboard summary endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from incident_triage_agent.api.dependencies import get_store
from incident_triage_agent.api.schemas import DashboardSummary

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard():
    store = get_store()
    incidents = list(store.incidents.values())

    priority_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    open_count = 0
    escalated = 0

    for inc in incidents:
        p = inc.get("priority", "P4")
        priority_counts[p] = priority_counts.get(p, 0) + 1
        cat = inc.get("classification", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        if inc.get("status") not in ("resolved", "false_positive"):
            open_count += 1
        if inc.get("status") == "escalated":
            escalated += 1

    top_cats = sorted(
        [{"category": k, "count": v} for k, v in category_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    return DashboardSummary(
        open_incidents=open_count,
        p1_count=priority_counts.get("P1", 0),
        p2_count=priority_counts.get("P2", 0),
        p3_count=priority_counts.get("P3", 0),
        p4_count=priority_counts.get("P4", 0),
        mttt_seconds=0.0,
        sla_compliance_pct=100.0,
        incidents_today=len(incidents),
        escalation_rate=round(escalated / len(incidents) * 100, 1) if incidents else 0.0,
        priority_breakdown=priority_counts,
        top_categories=top_cats,
    )
