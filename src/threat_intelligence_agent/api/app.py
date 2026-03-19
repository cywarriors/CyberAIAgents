"""FastAPI BFF application for the Threat Intelligence Agent GUI."""

from __future__ import annotations

import re

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from threat_intelligence_agent.api.routes import (
    actors,
    admin,
    briefs,
    dashboard,
    feeds,
    iocs,
    processing,
    websocket,
)


# ── Security Headers Middleware (OWASP) ──────────────────────────────────────

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


# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Threat Intelligence Agent — BFF API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.internal"],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3009",
        "http://localhost:5173",
        "http://127.0.0.1:3009",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Route registration ───────────────────────────────────────────────────────
app.include_router(dashboard.router)
app.include_router(iocs.router)
app.include_router(briefs.router)
app.include_router(actors.router)
app.include_router(feeds.router)
app.include_router(processing.router)
app.include_router(admin.router)
app.include_router(websocket.router)


# ── Input validation helper ──────────────────────────────────────────────────

_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def validate_id(value: str) -> str:
    """Validate that a path-parameter ID is safe."""
    if not _ID_PATTERN.match(value):
        from fastapi import HTTPException

        raise HTTPException(status_code=422, detail="Invalid identifier format")
    return value


@app.get("/healthz")
async def healthz():
    return {"status": "healthy"}
