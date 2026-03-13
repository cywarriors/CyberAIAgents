"""FastAPI schemas for Cloud Security Posture Management Agent."""

from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, Any


class FindingResponse(BaseModel):
    """API response for a misconfiguration finding."""
    finding_id: str
    rule_id: str
    rule_name: str
    resource_id: str
    resource_type: str
    resource_name: str
    account_id: str
    provider: str
    region: str
    severity: str
    risk_score: float
    risk_tier: str
    framework: str
    control_id: str
    remediation_status: str
    ticket_id: Optional[str] = None


class FindingDetailResponse(BaseModel):
    """Detailed finding with remediation guidance."""
    finding_id: str
    rule_id: str
    rule_name: str
    description: str
    resource_id: str
    resource_type: str
    resource_name: str
    account_id: str
    provider: str
    region: str
    severity: str
    risk_score: float
    risk_tier: str
    risk_explanation: str
    blast_radius: str
    exposure_level: str
    framework: str
    control_id: str
    evidence: dict[str, Any]
    remediation_guidance: str
    iac_fix_snippet: str
    cli_fix_command: str
    remediation_status: str
    ticket_id: Optional[str] = None
    first_detected: datetime
    last_evaluated: datetime


class AccountResponse(BaseModel):
    """Cloud account summary."""
    account_id: str
    account_name: str
    provider: str
    environment: str
    compliance_score: float
    total_resources: int
    total_findings: int
    critical_findings: int


class ComplianceScoreResponse(BaseModel):
    """Compliance scorecard entry."""
    account_id: str
    framework: str
    total_controls: int
    passed_controls: int
    failed_controls: int
    score_percent: float
    score_trend: str


class IaCScanResultResponse(BaseModel):
    """IaC scan result."""
    scan_id: str
    template_path: str
    framework: str
    repository: str
    branch: str
    total_resources: int
    passed_checks: int
    failed_checks: int
    findings_count: int
    scan_duration_seconds: float
    scanned_at: datetime


class IaCScanRequest(BaseModel):
    """Request to trigger IaC scan."""
    template_content: str = Field(..., min_length=1, max_length=1_000_000)
    template_path: str = Field(..., min_length=1, max_length=512)
    framework: str = Field("terraform", pattern="^(terraform|cloudformation|bicep|pulumi)$")
    repository: str = Field("", max_length=512)
    branch: str = Field("main", max_length=128)


class DriftResponse(BaseModel):
    """Configuration drift record."""
    drift_id: str
    resource_id: str
    resource_type: str
    account_id: str
    provider: str
    field_changed: str
    previous_value: str
    current_value: str
    drift_type: str
    detected_at: datetime


class ExposureAlertResponse(BaseModel):
    """Public exposure alert."""
    resource_id: str
    resource_type: str
    resource_name: str
    account_id: str
    provider: str
    region: str
    exposure_level: str
    blast_radius: str
    associated_findings: int
    risk_score: float


class DashboardPostureResponse(BaseModel):
    """Aggregated posture dashboard metrics."""
    total_accounts: int
    total_resources: int
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_provider: dict[str, int]
    overall_compliance_score: float
    compliance_by_framework: dict[str, float]
    public_exposure_count: int
    drift_count_24h: int
    iac_scans_count: int
    iac_block_rate: float
    top_non_compliant_services: list[dict[str, Any]]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    message: str
    components: dict[str, str]
    last_check: datetime


class ProcessingResultResponse(BaseModel):
    """Result of a CSPM scan pipeline."""
    success: bool
    total_resources_scanned: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    compliance_scores_computed: int
    tickets_created: int
    alerts_sent: int
    drift_records: int
    errors: list[str] = []
    processing_time_seconds: float
