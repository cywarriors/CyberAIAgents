"""FastAPI BFF application for the Compliance and Audit Agent GUI."""

from __future__ import annotations

import re

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from compliance_audit_agent.api.routes import (
    admin,
    dashboard,
    evidence,
    gaps,
    audit_packs,
    frameworks,
    sources,
    processing,
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


app = FastAPI(
    title="Compliance and Audit Agent — BFF API",
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
        "http://localhost:3010",
        "http://localhost:5173",
        "http://127.0.0.1:3010",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router)
app.include_router(evidence.router)
app.include_router(gaps.router)
app.include_router(audit_packs.router)
app.include_router(frameworks.router)
app.include_router(sources.router)
app.include_router(processing.router)
app.include_router(admin.router)


_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@app.get("/healthz")
async def healthz():
    return {"status": "healthy"}
