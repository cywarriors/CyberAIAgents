"""Drift detection and exposure alerts API endpoints."""

from fastapi import APIRouter, Query
from cloud_security_agent.api.schemas import DriftResponse, ExposureAlertResponse

router = APIRouter(prefix="/api/v1", tags=["drift-exposure"])


@router.get("/drift", response_model=list[DriftResponse])
async def get_drift_records(
    account_id: str = Query(None, max_length=128),
    drift_type: str = Query(None, pattern="^(security_regression|improvement|neutral)$"),
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(20, ge=1, le=100),
):
    """Configuration drift between scans."""

    drifts = [
        DriftResponse(drift_id="drift-001", resource_id="aws-prod-001-s3-001", resource_type="s3_bucket", account_id="aws-prod-001", provider="aws", field_changed="public_access_enabled", previous_value="False", current_value="True", drift_type="security_regression", detected_at="2026-03-13T06:30:00Z"),
        DriftResponse(drift_id="drift-002", resource_id="aws-prod-001-rds-001", resource_type="rds_instance", account_id="aws-prod-001", provider="aws", field_changed="encryption_enabled", previous_value="False", current_value="True", drift_type="improvement", detected_at="2026-03-13T05:45:00Z"),
        DriftResponse(drift_id="drift-003", resource_id="azure-prod-001-sa-002", resource_type="storage_account", account_id="azure-prod-001", provider="azure", field_changed="tls_version", previous_value="1.2", current_value="1.0", drift_type="security_regression", detected_at="2026-03-13T04:15:00Z"),
        DriftResponse(drift_id="drift-004", resource_id="gcp-prod-001-gcs-001", resource_type="gcs_bucket", account_id="gcp-prod-001", provider="gcp", field_changed="versioning_enabled", previous_value="True", current_value="False", drift_type="security_regression", detected_at="2026-03-13T03:00:00Z"),
        DriftResponse(drift_id="drift-005", resource_id="aws-prod-002-iam-003", resource_type="iam_user", account_id="aws-prod-002", provider="aws", field_changed="mfa_enabled", previous_value="False", current_value="True", drift_type="improvement", detected_at="2026-03-13T02:30:00Z"),
    ]

    if account_id:
        drifts = [d for d in drifts if d.account_id == account_id]
    if drift_type:
        drifts = [d for d in drifts if d.drift_type == drift_type]

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    return drifts[start_idx:end_idx]


@router.get("/exposure/alerts", response_model=list[ExposureAlertResponse])
async def get_exposure_alerts():
    """Public exposure alert feed."""

    return [
        ExposureAlertResponse(resource_id="aws-prod-001-s3-003", resource_type="s3_bucket", resource_name="public-assets-bucket", account_id="aws-prod-001", provider="aws", region="us-east-1", exposure_level="public", blast_radius="account-wide", associated_findings=3, risk_score=92.5),
        ExposureAlertResponse(resource_id="aws-prod-002-rds-002", resource_type="rds_instance", resource_name="reporting-db", account_id="aws-prod-002", provider="aws", region="us-west-2", exposure_level="public", blast_radius="region-wide", associated_findings=2, risk_score=88.0),
        ExposureAlertResponse(resource_id="azure-prod-001-sa-003", resource_type="storage_account", resource_name="shared-storage", account_id="azure-prod-001", provider="azure", region="eastus", exposure_level="internet_facing", blast_radius="resource-level", associated_findings=1, risk_score=75.5),
        ExposureAlertResponse(resource_id="gcp-prod-001-gcs-002", resource_type="gcs_bucket", resource_name="data-export-bucket", account_id="gcp-prod-001", provider="gcp", region="us-central1", exposure_level="public", blast_radius="resource-level", associated_findings=2, risk_score=82.0),
        ExposureAlertResponse(resource_id="aws-prod-001-ec2-005", resource_type="ec2_instance", resource_name="legacy-api-server", account_id="aws-prod-001", provider="aws", region="us-east-1", exposure_level="internet_facing", blast_radius="resource-level", associated_findings=4, risk_score=70.0),
    ]
