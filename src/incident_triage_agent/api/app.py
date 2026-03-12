"""FastAPI application for the Incident Triage Agent BFF."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from incident_triage_agent.api.routes import (
    analysts,
    dashboard,
    incidents,
    triage,
    websocket,
)

app = FastAPI(
    title="Incident Triage Agent BFF",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5175", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router)
app.include_router(incidents.router)
app.include_router(analysts.router)
app.include_router(triage.router)
app.include_router(websocket.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
