"""Administration endpoints – system health, audit."""

from __future__ import annotations

import time

from fastapi import APIRouter

from vapt_agent.api.dependencies import get_store
from vapt_agent.api.schemas import SystemHealthResponse

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/health", response_model=SystemHealthResponse)
async def system_health():
    store = get_store()
    uptime = time.time() - store._start_time
    return {
        "status": "healthy",
        "uptime_seconds": round(uptime, 2),
        "scanner_engines": {
            "nmap": "active",
            "zap": "active",
            "nuclei": "active",
            "burp": "active",
        },
        "kafka_connected": False,
        "redis_connected": False,
        "postgres_connected": False,
    }
