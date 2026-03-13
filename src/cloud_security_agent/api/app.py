"""FastAPI application for Cloud Security Posture Management Agent."""

import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from cloud_security_agent.config import settings
from cloud_security_agent.api.routes import findings, dashboard, accounts, compliance, iac, drift_exposure, admin

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
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'"
        return response


ALLOWED_ORIGINS = [
    origin.strip()
    for origin in settings.allowed_origins.split(",")
    if origin.strip()
]

app = FastAPI(
    title="Cloud Security Posture Management Agent",
    description="AI-powered multi-cloud compliance and misconfiguration detection",
    version="1.0.0",
    docs_url="/docs" if settings.cspm_api_debug else None,
    redoc_url="/redoc" if settings.cspm_api_debug else None,
)

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# Trusted host protection
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts.split(","),
)

# Include routers
app.include_router(findings.router)
app.include_router(dashboard.router)
app.include_router(accounts.router)
app.include_router(compliance.router)
app.include_router(iac.router)
app.include_router(drift_exposure.router)
app.include_router(admin.router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Cloud Security Posture Management Agent API",
        "version": "1.0.0",
        "health": "/api/v1/admin/health",
    }


@app.get("/api/v1")
async def api_root():
    """API v1 root."""
    return {
        "version": "1.0.0",
        "endpoints": {
            "findings": "/api/v1/findings",
            "accounts": "/api/v1/accounts",
            "compliance": "/api/v1/compliance",
            "iac": "/api/v1/iac",
            "drift": "/api/v1/drift",
            "exposure": "/api/v1/exposure/alerts",
            "dashboard": "/api/v1/dashboard/posture",
            "admin": "/api/v1/admin",
        },
    }


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions without leaking internal details."""
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.cspm_api_host,
        port=settings.cspm_api_port,
        log_level=settings.log_level,
    )
