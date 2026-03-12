"""Pipeline health monitoring endpoint."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from threat_detection_agent.api.dependencies import get_store
from threat_detection_agent.api.schemas import NodeHealth, PipelineHealthResponse

router = APIRouter(prefix="/api/v1/pipeline", tags=["pipeline"])

_PIPELINE_NODES = ["ingest", "normalize", "rule_match", "anomaly", "deduplicate", "score", "publish", "feedback"]


@router.get("/health", response_model=PipelineHealthResponse)
async def get_pipeline_health():
    store = get_store()
    now = datetime.now(timezone.utc).isoformat()
    nodes = [
        NodeHealth(
            node_name=name,
            status="healthy",
            events_processed=0,
            errors=0,
            avg_latency_ms=0.0,
            last_heartbeat=now,
        )
        for name in _PIPELINE_NODES
    ]
    return PipelineHealthResponse(
        status="healthy",
        uptime_seconds=store.uptime,
        nodes=nodes,
        kafka_connected=False,
        redis_connected=False,
        postgres_connected=False,
        queue_depth=0,
    )
