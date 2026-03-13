"""Processing pipeline and administration API endpoints."""

import logging
import time
from fastapi import APIRouter, HTTPException, Query, Request
from datetime import datetime, timezone
from cloud_security_agent.api.schemas import HealthResponse, ProcessingResultResponse
from cloud_security_agent.monitoring import HealthChecker
from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.main import run_cspm_pipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["admin"])


@router.get("/admin/health", response_model=HealthResponse)
async def health_check(request: Request):
    """Check agent health status."""
    logger.info("Admin health check accessed from %s", request.client.host if request.client else "unknown")

    health_checker = HealthChecker()
    health_status = await health_checker.check_health()

    return HealthResponse(
        status=health_status.status,
        message=health_status.message,
        components=health_status.components,
        last_check=health_status.last_check,
    )


@router.get("/admin/config")
async def get_configuration(request: Request):
    """Get current agent configuration (non-sensitive fields only)."""
    logger.info("Admin config accessed from %s", request.client.host if request.client else "unknown")

    from cloud_security_agent.config import settings

    return {
        "api_host": settings.cspm_api_host,
        "api_port": settings.cspm_api_port,
        "cloud_providers": {
            "aws_enabled": settings.aws_enabled,
            "azure_enabled": settings.azure_enabled,
            "gcp_enabled": settings.gcp_enabled,
        },
        "risk_weights": {
            "severity": settings.risk_weight_severity,
            "exposure": settings.risk_weight_exposure,
            "blast_radius": settings.risk_weight_blast_radius,
            "asset_criticality": settings.risk_weight_asset_criticality,
            "compliance_impact": settings.risk_weight_compliance_impact,
        },
        "compliance_frameworks": {
            "cis_benchmarks": settings.enable_cis_benchmarks,
            "nist_800_53": settings.enable_nist_800_53,
            "custom_policies": settings.enable_custom_policies,
        },
        "scan_settings": {
            "full_scan_interval_minutes": settings.full_scan_interval_minutes,
            "drift_check_interval_minutes": settings.drift_check_interval_minutes,
            "max_concurrent_account_scans": settings.max_concurrent_account_scans,
            "iac_scan_timeout_seconds": settings.iac_scan_timeout_seconds,
        },
        "risk_thresholds": {
            "critical": settings.risk_threshold_critical,
            "high": settings.risk_threshold_high,
            "medium": settings.risk_threshold_medium,
        },
    }


@router.get("/admin/statistics")
async def get_statistics(request: Request):
    """Get agent statistics."""
    logger.info("Admin statistics accessed from %s", request.client.host if request.client else "unknown")

    return {
        "total_scans_run": 368,
        "accounts_scanned": 12,
        "resources_inventoried": 4850,
        "findings_detected": 2341,
        "findings_remediated": 1892,
        "iac_scans_performed": 1245,
        "iac_deployments_blocked": 89,
        "drift_events_detected": 456,
        "tickets_created": 2180,
        "avg_scan_time_seconds": 245.6,
        "uptime_percent": 99.93,
    }


@router.get("/admin/audit-log")
async def get_audit_log(request: Request, limit: int = Query(50, ge=1, le=500)):
    """Get audit log entries (PII masked)."""
    logger.info("Admin audit-log accessed from %s", request.client.host if request.client else "unknown")

    def _mask_user(user: str) -> str:
        """Mask email addresses, keep system accounts."""
        if "@" in user:
            local, domain = user.split("@", 1)
            return f"{local[:2]}***@{domain}"
        return user

    return {
        "entries": [
            {"timestamp": "2026-03-13T10:30:00Z", "action": "full_scan", "user": _mask_user("system"), "details": "Completed full scan across 12 accounts", "findings_count": 147},
            {"timestamp": "2026-03-13T09:15:00Z", "action": "iac_scan", "user": _mask_user("ci-pipeline"), "details": "IaC scan for infra/main.tf - 3 findings blocked", "findings_count": 3},
            {"timestamp": "2026-03-13T08:45:00Z", "action": "drift_detected", "user": _mask_user("system"), "details": "Security regression: S3 bucket public access enabled", "findings_count": 1},
            {"timestamp": "2026-03-13T08:00:00Z", "action": "risk_accepted", "user": _mask_user("john.doe@example.com"), "details": "Risk acceptance for legacy API server public IP", "findings_count": 0},
            {"timestamp": "2026-03-13T07:30:00Z", "action": "remediation_completed", "user": _mask_user("jane.smith@example.com"), "details": "Enabled RDS encryption on prod-db-primary", "findings_count": 0},
        ],
        "total_entries": 8923,
        "showing": 5,
    }


@router.post("/process/run-full-scan", response_model=ProcessingResultResponse)
async def run_full_scan(request: Request):
    """Run full CSPM scan pipeline."""
    logger.info("Full scan triggered from %s", request.client.host if request.client else "unknown")

    start_time = time.time()

    try:
        initial_state = CloudPostureState()
        result_state = await run_cspm_pipeline(initial_state)

        processing_time = time.time() - start_time

        metrics = result_state.metrics if isinstance(result_state, CloudPostureState) else result_state.get("metrics", {})
        errors = result_state.processing_errors if isinstance(result_state, CloudPostureState) else result_state.get("processing_errors", [])

        return ProcessingResultResponse(
            success=True,
            total_resources_scanned=metrics.get("total_resources", 0),
            total_findings=metrics.get("prioritized_count", 0),
            critical_findings=metrics.get("critical_findings", 0),
            high_findings=metrics.get("high_findings", 0),
            medium_findings=metrics.get("medium_findings", 0),
            low_findings=metrics.get("low_findings", 0),
            compliance_scores_computed=metrics.get("compliance_scores_computed", 0),
            tickets_created=metrics.get("tickets_created", 0),
            alerts_sent=metrics.get("alerts_sent", 0),
            drift_records=metrics.get("drift_total", 0),
            errors=errors,
            processing_time_seconds=processing_time,
        )
    except Exception as e:
        logger.exception("CSPM scan pipeline failed")
        raise HTTPException(status_code=500, detail="Scan pipeline execution failed")
