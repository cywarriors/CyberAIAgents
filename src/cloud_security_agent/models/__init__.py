"""Data models for the Cloud Security Posture Management Agent."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from enum import Enum


def _utcnow():
    return datetime.now(timezone.utc)


class CloudProvider(str, Enum):
    """Supported cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class SeverityLevel(str, Enum):
    """Finding severity classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStatus(str, Enum):
    """Compliance check status."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class RemediationStatus(str, Enum):
    """Remediation tracking status."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    RISK_ACCEPTED = "risk_accepted"
    DEFERRED = "deferred"


class ExposureLevel(str, Enum):
    """Resource exposure classification."""
    PUBLIC = "public"
    INTERNET_FACING = "internet_facing"
    INTERNAL = "internal"
    PRIVATE = "private"


class IaCFramework(str, Enum):
    """Infrastructure-as-Code framework."""
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    BICEP = "bicep"
    PULUMI = "pulumi"


@dataclass
class CloudAccount:
    """Cloud provider account/subscription/project."""
    account_id: str
    account_name: str
    provider: CloudProvider
    environment: str  # prod, staging, dev
    owner_email: str
    regions: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    last_scan_time: Optional[datetime] = None
    compliance_score: float = 0.0


@dataclass
class CloudResource:
    """Individual cloud resource."""
    resource_id: str
    resource_arn: str
    resource_type: str  # e.g., s3_bucket, ec2_instance, rds_instance
    resource_name: str
    provider: CloudProvider
    account_id: str
    region: str
    configuration: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    exposure: ExposureLevel = ExposureLevel.PRIVATE
    criticality: str = "medium"  # critical, high, medium, low
    created_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None


@dataclass
class PolicyRule:
    """Security policy rule for evaluation."""
    rule_id: str
    rule_name: str
    description: str
    framework: str  # CIS, NIST, custom
    control_id: str  # e.g., CIS 2.1.1, NIST AC-2
    severity: SeverityLevel
    resource_types: list[str] = field(default_factory=list)
    providers: list[CloudProvider] = field(default_factory=list)
    remediation_guidance: str = ""
    iac_fix_template: str = ""
    cli_fix_command: str = ""


@dataclass
class PolicyFinding:
    """Result of a policy evaluation against a resource."""
    finding_id: str
    rule_id: str
    rule_name: str
    resource_id: str
    resource_type: str
    resource_name: str
    account_id: str
    provider: CloudProvider
    region: str
    status: ComplianceStatus
    severity: SeverityLevel
    framework: str
    control_id: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation_guidance: str = ""
    iac_fix_snippet: str = ""
    cli_fix_command: str = ""
    first_detected: datetime = field(default_factory=_utcnow)
    last_evaluated: datetime = field(default_factory=_utcnow)
    remediation_status: RemediationStatus = RemediationStatus.OPEN
    ticket_id: Optional[str] = None


@dataclass
class IaCScanResult:
    """Result of an IaC template scan."""
    scan_id: str
    template_path: str
    framework: IaCFramework
    repository: str
    branch: str
    findings: list[PolicyFinding] = field(default_factory=list)
    total_resources: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    scan_duration_seconds: float = 0.0
    scanned_at: datetime = field(default_factory=_utcnow)


@dataclass
class PrioritizedFinding:
    """Finding enriched with risk priority information."""
    finding: PolicyFinding
    composite_risk_score: float  # 0-100
    risk_tier: SeverityLevel
    blast_radius: str  # account-wide, region-wide, resource-level
    exposure_level: ExposureLevel
    asset_criticality: str
    compliance_frameworks_affected: list[str] = field(default_factory=list)
    risk_explanation: str = ""
    # Score components for explainability
    severity_score: float = 0.0
    exposure_score: float = 0.0
    blast_radius_score: float = 0.0
    criticality_score: float = 0.0
    compliance_score: float = 0.0


@dataclass
class DriftRecord:
    """Configuration drift between scan snapshots."""
    drift_id: str
    resource_id: str
    resource_type: str
    account_id: str
    provider: CloudProvider
    field_changed: str
    previous_value: str
    current_value: str
    drift_type: str  # security_regression, improvement, neutral
    detected_at: datetime = field(default_factory=_utcnow)
    attributed_to: str = ""  # user/service that made the change


@dataclass
class ComplianceScore:
    """Compliance score for an account/framework combination."""
    account_id: str
    framework: str
    total_controls: int
    passed_controls: int
    failed_controls: int
    not_applicable_controls: int
    score_percent: float
    previous_score_percent: float = 0.0
    score_trend: str = "stable"  # improving, declining, stable
    evaluated_at: datetime = field(default_factory=_utcnow)


@dataclass
class DashboardMetrics:
    """Dashboard-ready aggregated CSPM metrics."""
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
    top_non_compliant_services: list[dict[str, Any]] = field(default_factory=list)
    dashboard_generated_at: datetime = field(default_factory=_utcnow)
