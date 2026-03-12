"""FastAPI application – VAPT Agent Backend-for-Frontend (BFF)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from vapt_agent.api.routes import (
    admin,
    attack_paths,
    compliance,
    dashboard,
    engagements,
    exploits,
    findings,
    reports,
    scans,
    websocket,
)

app = FastAPI(
    title="VAPT Agent GUI – BFF API",
    version="1.0.0",
    description="Backend-for-Frontend serving the VAPT Agent React dashboard.",
)

# CORS – allow the React dev server and production origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all route modules
app.include_router(dashboard.router)
app.include_router(engagements.router)
app.include_router(findings.router)
app.include_router(scans.router)
app.include_router(attack_paths.router)
app.include_router(exploits.router)
app.include_router(reports.router)
app.include_router(compliance.router)
app.include_router(admin.router)
app.include_router(websocket.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
