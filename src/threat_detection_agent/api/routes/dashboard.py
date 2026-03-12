"""Dashboard metrics aggregation endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from threat_detection_agent.api.dependencies import get_store
from threat_detection_agent.api.schemas import DashboardMetrics

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics():
    store = get_store()
    alerts = list(store.alerts.values())

    sev_counts: dict[str, int] = {}
    for a in alerts:
        sev = a.get("severity", "Info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Top triggered rules by hit_count
    rule_hits = sorted(
        store.rules.values(),
        key=lambda r: r.get("hit_count", 0),
        reverse=True,
    )[:5]
    top_rules = [
        {"rule_id": r["rule_id"], "rule_name": r["rule_name"], "hit_count": r.get("hit_count", 0)}
        for r in rule_hits
    ]

    return DashboardMetrics(
        total_alerts=len(alerts),
        critical_alerts=sev_counts.get("Critical", 0),
        high_alerts=sev_counts.get("High", 0),
        medium_alerts=sev_counts.get("Medium", 0),
        low_alerts=sev_counts.get("Low", 0),
        info_alerts=sev_counts.get("Info", 0),
        active_anomalies=len(store.anomalies),
        rules_deployed=sum(
            1 for r in store.rules.values() if r.get("status") == "production"
        ),
        mttd_seconds=0.0,
        pipeline_throughput_eps=0.0,
        severity_breakdown=sev_counts,
        top_triggered_rules=top_rules,
        alert_volume_timeline=[],
    )
