"""FastAPI application for Identity & Access Monitoring Agent BFF."""

import logging
import re

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from identity_access_agent.config import get_settings
from identity_access_agent.api.routes import (
    dashboard,
    alerts,
    risk_scores,
    users,
    sod_violations,
    recommendations,
    processing,
    admin,
)

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        return response


settings = get_settings()

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in settings.allowed_origins.split(",")
    if origin.strip()
]

app = FastAPI(
    title="Identity & Access Monitoring Agent",
    description="AI-powered identity risk detection, access anomaly analysis, and automated response",
    version="1.0.0",
    docs_url="/docs" if settings.api_debug else None,
    redoc_url="/redoc" if settings.api_debug else None,
)

# Security middleware chain
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts.split(","),
)

# Include routers
app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(risk_scores.router)
app.include_router(users.router)
app.include_router(sod_violations.router)
app.include_router(recommendations.router)
app.include_router(processing.router)
app.include_router(admin.router)


@app.get("/")
async def root():
    return {
        "message": "Identity & Access Monitoring Agent API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/admin/health",
    }


@app.get("/api/v1")
async def api_root():
    return {
        "version": "1.0.0",
        "endpoints": {
            "dashboard": "/api/v1/dashboard",
            "alerts": "/api/v1/alerts",
            "risk_scores": "/api/v1/risk-scores",
            "users": "/api/v1/users",
            "sod_violations": "/api/v1/sod-violations",
            "recommendations": "/api/v1/recommendations",
            "processing": "/api/v1/process",
            "admin": "/api/v1/admin",
        },
    }


_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")


def validate_id(value: str) -> str:
    """Validate a path-parameter ID."""
    if not _SAFE_ID_RE.match(value):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Invalid identifier format")
    return value


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
