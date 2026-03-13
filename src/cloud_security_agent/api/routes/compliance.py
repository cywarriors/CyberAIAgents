"""Compliance scorecard API endpoints."""

from fastapi import APIRouter, Query
from cloud_security_agent.api.schemas import ComplianceScoreResponse

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])


@router.get("/scores", response_model=list[ComplianceScoreResponse])
async def get_compliance_scores(
    framework: str = Query(None, max_length=64),
    account_id: str = Query(None, max_length=128),
):
    """Compliance scorecard by benchmark and account."""

    scores = [
        ComplianceScoreResponse(account_id="aws-prod-001", framework="CIS", total_controls=120, passed_controls=102, failed_controls=18, score_percent=85.0, score_trend="improving"),
        ComplianceScoreResponse(account_id="aws-prod-001", framework="NIST", total_controls=95, passed_controls=74, failed_controls=21, score_percent=77.9, score_trend="stable"),
        ComplianceScoreResponse(account_id="aws-prod-002", framework="CIS", total_controls=120, passed_controls=106, failed_controls=14, score_percent=88.3, score_trend="improving"),
        ComplianceScoreResponse(account_id="azure-prod-001", framework="CIS", total_controls=110, passed_controls=93, failed_controls=17, score_percent=84.5, score_trend="stable"),
        ComplianceScoreResponse(account_id="azure-prod-001", framework="NIST", total_controls=95, passed_controls=76, failed_controls=19, score_percent=80.0, score_trend="improving"),
        ComplianceScoreResponse(account_id="gcp-prod-001", framework="CIS", total_controls=100, passed_controls=81, failed_controls=19, score_percent=81.0, score_trend="declining"),
        ComplianceScoreResponse(account_id="gcp-prod-001", framework="NIST", total_controls=95, passed_controls=72, failed_controls=23, score_percent=75.8, score_trend="stable"),
    ]

    if framework:
        scores = [s for s in scores if s.framework == framework]
    if account_id:
        scores = [s for s in scores if s.account_id == account_id]

    return scores


@router.get("/controls")
async def get_compliance_controls(
    framework: str = Query("CIS", max_length=64),
    account_id: str = Query(None, max_length=128),
):
    """Control-level pass/fail detail."""

    return [
        {"control_id": "CIS 1.2", "control_name": "IAM User MFA Enabled", "status": "fail", "affected_resources": 3, "severity": "critical"},
        {"control_id": "CIS 1.16", "control_name": "IAM Excessive Permissions", "status": "fail", "affected_resources": 5, "severity": "high"},
        {"control_id": "CIS 2.1.1", "control_name": "S3 Bucket Encryption", "status": "fail", "affected_resources": 4, "severity": "high"},
        {"control_id": "CIS 2.1.2", "control_name": "S3 Public Access Block", "status": "fail", "affected_resources": 2, "severity": "critical"},
        {"control_id": "CIS 2.1.3", "control_name": "S3 Bucket Versioning", "status": "pass", "affected_resources": 0, "severity": "medium"},
        {"control_id": "CIS 2.3.1", "control_name": "RDS Encryption at Rest", "status": "fail", "affected_resources": 1, "severity": "high"},
        {"control_id": "CIS 2.3.2", "control_name": "Database Public Access", "status": "pass", "affected_resources": 0, "severity": "critical"},
        {"control_id": "CIS 3.1", "control_name": "CloudTrail Logging", "status": "pass", "affected_resources": 0, "severity": "high"},
        {"control_id": "CIS 4.1.1", "control_name": "VM Public IP Restrictions", "status": "fail", "affected_resources": 2, "severity": "high"},
        {"control_id": "NIST SC-8", "control_name": "Minimum TLS Version 1.2", "status": "fail", "affected_resources": 3, "severity": "high"},
        {"control_id": "NIST SC-12", "control_name": "Encryption Key Rotation", "status": "fail", "affected_resources": 4, "severity": "medium"},
        {"control_id": "NIST SC-28", "control_name": "Storage Encryption", "status": "pass", "affected_resources": 0, "severity": "high"},
    ]
