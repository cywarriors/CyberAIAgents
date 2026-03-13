"""Health check and readiness probe endpoint."""

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

app = FastAPI(title="Phishing Defense Agent – Health", docs_url=None, redoc_url=None)

_ready = False


def set_ready(state: bool = True) -> None:
    global _ready
    _ready = state


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness probe – always returns 200."""
    return {"status": "ok"}


@app.get("/readyz")
def readyz(response: Response) -> dict[str, str]:
    """Readiness probe – 200 only when pipeline is ready."""
    if _ready:
        return {"status": "ready"}
    response.status_code = 503
    return {"status": "not_ready"}


@app.get("/metrics")
def metrics() -> Response:
    """Expose Prometheus metrics."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
