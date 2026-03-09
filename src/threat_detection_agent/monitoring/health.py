"""Health check & readiness probe endpoint (§10, §11)."""

from __future__ import annotations

from fastapi import FastAPI, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

app = FastAPI(title="Threat Detection Agent – Health", docs_url=None, redoc_url=None)

_ready = False


def set_ready(state: bool = True) -> None:
    global _ready
    _ready = state


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness probe – always returns 200 if process is up."""
    return {"status": "ok"}


@app.get("/readyz")
def readyz(response: Response) -> dict[str, str]:
    """Readiness probe – returns 200 only when the pipeline is ready."""
    if _ready:
        return {"status": "ready"}
    response.status_code = 503
    return {"status": "not_ready"}


@app.get("/metrics")
def metrics() -> Response:
    """Expose Prometheus metrics."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
