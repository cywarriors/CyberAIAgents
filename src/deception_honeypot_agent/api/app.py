"""FastAPI BFF application for the Deception Honeypot Agent."""
from __future__ import annotations

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from deception_honeypot_agent.api.routes import (
    admin,
    alerts,
    coverage,
    dashboard,
    decoys,
    interactions,
    pipeline,
    profiles,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


app = FastAPI(title="Deception Honeypot Agent — BFF API", version="1.0.0")

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.internal"],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3012",
        "http://127.0.0.1:3012",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin.router)
app.include_router(dashboard.router)
app.include_router(decoys.router)
app.include_router(interactions.router)
app.include_router(alerts.router)
app.include_router(coverage.router)
app.include_router(profiles.router)
app.include_router(pipeline.router)


@app.get("/healthz")
async def healthz():
    return {"status": "healthy"}
