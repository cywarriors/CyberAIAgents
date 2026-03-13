"""Dashboard and posture metrics API endpoints."""

from fastapi import APIRouter
from cloud_security_agent.api.schemas import DashboardPostureResponse

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/posture", response_model=DashboardPostureResponse)
async def get_posture_dashboard():
    """Aggregated posture dashboard metrics."""

    return DashboardPostureResponse(
        total_accounts=12,
        total_resources=4850,
        total_findings=147,
        findings_by_severity={"critical": 8, "high": 32, "medium": 64, "low": 43},
        findings_by_provider={"aws": 72, "azure": 45, "gcp": 30},
        overall_compliance_score=82.5,
        compliance_by_framework={"CIS": 85.0, "NIST": 78.5},
        public_exposure_count=5,
        drift_count_24h=14,
        iac_scans_count=38,
        iac_block_rate=91.2,
        top_non_compliant_services=[
            {"service": "S3", "finding_count": 22, "provider": "aws"},
            {"service": "IAM", "finding_count": 18, "provider": "aws"},
            {"service": "Storage Accounts", "finding_count": 12, "provider": "azure"},
            {"service": "Compute Engine", "finding_count": 10, "provider": "gcp"},
            {"service": "RDS", "finding_count": 9, "provider": "aws"},
        ],
    )


@router.get("/compliance-trend")
async def get_compliance_trend():
    """Compliance score trend over time."""

    return {
        "period": "30d",
        "data": [
            {"date": "2026-02-12", "score": 76.2},
            {"date": "2026-02-19", "score": 78.1},
            {"date": "2026-02-26", "score": 79.8},
            {"date": "2026-03-05", "score": 81.3},
            {"date": "2026-03-12", "score": 82.5},
        ],
    }


@router.get("/findings-by-service")
async def get_findings_by_service():
    """Findings grouped by cloud service."""

    return [
        {"service": "S3", "provider": "aws", "critical": 3, "high": 8, "medium": 7, "low": 4},
        {"service": "IAM", "provider": "aws", "critical": 4, "high": 6, "medium": 5, "low": 3},
        {"service": "RDS", "provider": "aws", "critical": 1, "high": 4, "medium": 3, "low": 1},
        {"service": "EC2", "provider": "aws", "critical": 0, "high": 3, "medium": 5, "low": 2},
        {"service": "Storage Accounts", "provider": "azure", "critical": 0, "high": 5, "medium": 4, "low": 3},
        {"service": "Key Vault", "provider": "azure", "critical": 0, "high": 2, "medium": 4, "low": 2},
        {"service": "Compute Engine", "provider": "gcp", "critical": 0, "high": 4, "medium": 4, "low": 2},
        {"service": "Cloud Storage", "provider": "gcp", "critical": 0, "high": 2, "medium": 5, "low": 3},
    ]


@router.get("/provider-summary")
async def get_provider_summary():
    """Summary metrics per cloud provider."""

    return {
        "aws": {
            "accounts": 5,
            "resources": 2100,
            "findings": 72,
            "compliance_score": 84.2,
        },
        "azure": {
            "accounts": 4,
            "resources": 1650,
            "findings": 45,
            "compliance_score": 81.0,
        },
        "gcp": {
            "accounts": 3,
            "resources": 1100,
            "findings": 30,
            "compliance_score": 79.5,
        },
    }
