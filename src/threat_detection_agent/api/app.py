"""FastAPI application for the Threat Detection Agent BFF."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from threat_detection_agent.api.routes import (
    alerts,
    anomalies,
    coverage,
    dashboard,
    pipeline,
    rules,
    tuning,
    websocket,
)

app = FastAPI(
    title="Threat Detection Agent BFF",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(rules.router)
app.include_router(anomalies.router)
app.include_router(coverage.router)
app.include_router(pipeline.router)
app.include_router(tuning.router)
app.include_router(websocket.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
