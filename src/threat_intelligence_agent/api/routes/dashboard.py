"""Dashboard endpoint — aggregated intelligence metrics."""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter

from threat_intelligence_agent.api.dependencies import get_store
from threat_intelligence_agent.api.schemas import DashboardMetricsResponse

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/intel", response_model=DashboardMetricsResponse)
async def get_dashboard_metrics() -> DashboardMetricsResponse:
    store = get_store()
    iocs = store.iocs
    feeds = store.feeds

    active = [i for i in iocs if i.get("lifecycle") == "active"]
    confs = [i.get("confidence", 0) for i in iocs if i.get("confidence")]
    avg_conf = sum(confs) / max(len(confs), 1)
    distributed = [i for i in active if i.get("confidence", 0) >= 70]
    op_rate = len(distributed) / max(len(active), 1) if active else 0

    type_dist = dict(Counter(i.get("ioc_type", "unknown") for i in iocs))

    actor_counts = Counter(i.get("actor", "") for i in iocs if i.get("actor"))
    top_actors = [{"name": a, "ioc_count": c} for a, c in actor_counts.most_common(5)]

    feed_health = [
        {"feed_id": f["feed_id"], "name": f["name"], "status": "healthy" if f.get("success_rate", 0) >= 0.9 else "degraded", "success_rate": f.get("success_rate", 0)}
        for f in feeds
    ]
    healthy_feeds = sum(1 for f in feeds if f.get("success_rate", 0) >= 0.9)

    return DashboardMetricsResponse(
        total_iocs=len(iocs),
        active_iocs=len(active),
        feeds_healthy=healthy_feeds,
        feeds_total=len(feeds),
        avg_confidence=round(avg_conf, 1),
        operationalization_rate=round(op_rate * 100, 1),
        briefs_published=len(store.briefs),
        active_actors=len(store.actors),
        ioc_type_distribution=type_dist,
        top_actors=top_actors,
        ingestion_timeline=[],
        feed_health=feed_health,
    )
