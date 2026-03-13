"""Cloud accounts API endpoints."""

from fastapi import APIRouter, Query, HTTPException
from cloud_security_agent.api.schemas import AccountResponse, ComplianceScoreResponse

router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


@router.get("", response_model=list[AccountResponse])
async def list_accounts():
    """List cloud accounts with compliance scores."""

    return [
        AccountResponse(account_id="aws-prod-001", account_name="AWS Production", provider="aws", environment="prod", compliance_score=86.5, total_resources=850, total_findings=28, critical_findings=3),
        AccountResponse(account_id="aws-prod-002", account_name="AWS Production US-West", provider="aws", environment="prod", compliance_score=88.2, total_resources=620, total_findings=18, critical_findings=1),
        AccountResponse(account_id="aws-staging-001", account_name="AWS Staging", provider="aws", environment="staging", compliance_score=79.1, total_resources=410, total_findings=15, critical_findings=0),
        AccountResponse(account_id="aws-dev-001", account_name="AWS Development", provider="aws", environment="dev", compliance_score=72.3, total_resources=220, total_findings=11, critical_findings=0),
        AccountResponse(account_id="azure-prod-001", account_name="Azure Production", provider="azure", environment="prod", compliance_score=84.0, total_resources=780, total_findings=22, critical_findings=2),
        AccountResponse(account_id="azure-prod-002", account_name="Azure Production EU", provider="azure", environment="prod", compliance_score=82.5, total_resources=520, total_findings=14, critical_findings=0),
        AccountResponse(account_id="azure-staging-001", account_name="Azure Staging", provider="azure", environment="staging", compliance_score=76.8, total_resources=350, total_findings=9, critical_findings=0),
        AccountResponse(account_id="gcp-prod-001", account_name="GCP Production", provider="gcp", environment="prod", compliance_score=81.2, total_resources=490, total_findings=16, critical_findings=1),
        AccountResponse(account_id="gcp-prod-002", account_name="GCP Analytics", provider="gcp", environment="prod", compliance_score=83.5, total_resources=380, total_findings=10, critical_findings=1),
        AccountResponse(account_id="gcp-dev-001", account_name="GCP Development", provider="gcp", environment="dev", compliance_score=68.9, total_resources=230, total_findings=4, critical_findings=0),
    ]


@router.get("/{account_id}/resources")
async def get_account_resources(
    account_id: str,
    resource_type: str = Query(None, max_length=64),
    page: int = Query(1, ge=1, le=10000),
    page_size: int = Query(20, ge=1, le=100),
):
    """Get resource inventory for a specific account."""

    resources = [
        {"resource_id": f"{account_id}-s3-001", "resource_type": "s3_bucket", "resource_name": "app-data-bucket", "region": "us-east-1", "exposure": "private", "criticality": "high"},
        {"resource_id": f"{account_id}-s3-002", "resource_type": "s3_bucket", "resource_name": "logs-bucket", "region": "us-east-1", "exposure": "private", "criticality": "medium"},
        {"resource_id": f"{account_id}-rds-001", "resource_type": "rds_instance", "resource_name": "prod-db-primary", "region": "us-east-1", "exposure": "private", "criticality": "critical"},
        {"resource_id": f"{account_id}-ec2-001", "resource_type": "ec2_instance", "resource_name": "web-server-1", "region": "us-east-1", "exposure": "internet_facing", "criticality": "high"},
        {"resource_id": f"{account_id}-iam-001", "resource_type": "iam_user", "resource_name": "admin-user", "region": "global", "exposure": "internal", "criticality": "critical"},
    ]

    if resource_type:
        resources = [r for r in resources if r["resource_type"] == resource_type]

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    return resources[start_idx:end_idx]
