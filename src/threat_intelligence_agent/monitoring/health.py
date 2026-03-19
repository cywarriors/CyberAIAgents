"""Health and readiness endpoints for the Threat Intelligence Agent."""

from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import generate_latest

health_app = FastAPI(title="Threat-Intel Health", docs_url=None, redoc_url=None)

_START_TIME = time.time()


@health_app.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "healthy", "uptime_seconds": round(time.time() - _START_TIME, 1)})


@health_app.get("/readyz")
async def readyz() -> JSONResponse:
    return JSONResponse({"status": "ready"})


@health_app.get("/metrics")
async def metrics() -> PlainTextResponse:
    return PlainTextResponse(generate_latest().decode(), media_type="text/plain; version=0.0.4")
