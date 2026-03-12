"""Health / readiness / metrics HTTP server for the VAPT agent."""

from __future__ import annotations

import threading

import structlog
import uvicorn
from fastapi import FastAPI
from prometheus_client import generate_latest

from vapt_agent.config import get_settings

logger = structlog.get_logger(__name__)

app = FastAPI(title="VAPT Agent Health", docs_url=None, redoc_url=None)

_ready = threading.Event()


def mark_ready() -> None:
    _ready.set()


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/readyz")
async def readyz():
    if _ready.is_set():
        return {"status": "ready"}
    return {"status": "not_ready"}, 503


@app.get("/metrics")
async def metrics():
    from starlette.responses import Response

    return Response(
        content=generate_latest(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


def start_health_server() -> threading.Thread:
    """Start the health-check HTTP server in a background daemon thread."""
    settings = get_settings()

    def _run():
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=settings.health_check_port,
            log_level="warning",
        )

    t = threading.Thread(target=_run, daemon=True, name="vapt-health")
    t.start()
    logger.info("health_server_started", port=settings.health_check_port)
    return t
