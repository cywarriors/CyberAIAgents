"""VAPT Agent data models – findings, exploits, assets, and reports."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ExploitRiskLevel(str, Enum):
    SAFE = "safe"
    MODERATE = "moderate"
    DESTRUCTIVE = "destructive"


class FindingStatus(str, Enum):
    OPEN = "open"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


class EngagementStatus(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ARCHIVED = "archived"


# ---------------------------------------------------------------------------
# Rules of Engagement
# ---------------------------------------------------------------------------

class RoERecord(BaseModel):
    """Rules of Engagement authorisation record."""

    roe_id: str
    engagement_name: str
    authorized_by: str
    approved_at: datetime = Field(default_factory=datetime.utcnow)
    scope_ips: list[str] = Field(default_factory=list)
    scope_domains: list[str] = Field(default_factory=list)
    scope_cloud_accounts: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    testing_window_start: str | None = None
    testing_window_end: str | None = None
    allow_destructive: bool = False
    status: EngagementStatus = EngagementStatus.APPROVED


# ---------------------------------------------------------------------------
# Discovered Assets
# ---------------------------------------------------------------------------

class DiscoveredAsset(BaseModel):
    """Asset discovered during enumeration phase."""

    asset_id: str
    ip: str
    hostname: str | None = None
    os_fingerprint: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    asset_type: str = "host"  # host | web_app | api | cloud_resource
    criticality: str = "medium"  # low | medium | high | critical
    cloud_provider: str | None = None
    cloud_resource_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Scan Findings
# ---------------------------------------------------------------------------

class ScanFinding(BaseModel):
    """Vulnerability finding from scanning phase."""

    finding_id: str
    asset_id: str
    scanner: str  # nmap | nuclei | zap | nessus | cloud_api
    cve_id: str | None = None
    cwe_id: str | None = None
    title: str
    description: str
    severity: Severity
    cvss_score: float | None = None
    epss_score: float | None = None
    affected_component: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation_guidance: str = ""
    status: FindingStatus = FindingStatus.OPEN


# ---------------------------------------------------------------------------
# Exploit Validation
# ---------------------------------------------------------------------------

class ExploitResult(BaseModel):
    """Result from safe exploitation validation."""

    exploit_id: str
    finding_id: str
    module_name: str
    risk_level: ExploitRiskLevel
    success: bool
    output: str = ""
    rollback_success: bool = True
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Attack Paths
# ---------------------------------------------------------------------------

class AttackPathStep(BaseModel):
    """Single step in an attack path chain."""

    step_number: int
    asset_id: str
    technique: str
    finding_id: str | None = None
    description: str = ""


class AttackPath(BaseModel):
    """Lateral movement chain from initial foothold to target."""

    path_id: str
    steps: list[AttackPathStep] = Field(default_factory=list)
    initial_foothold_asset: str = ""
    target_asset: str = ""
    total_severity: Severity = Severity.HIGH
    mitre_technique_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scored Findings
# ---------------------------------------------------------------------------

class ScoredFinding(BaseModel):
    """Finding with composite risk score."""

    finding_id: str
    asset_id: str
    severity: Severity
    composite_score: float = Field(..., ge=0.0, le=100.0)
    cvss_component: float = 0.0
    epss_component: float = 0.0
    exploitability_component: float = 0.0
    asset_criticality_component: float = 0.0
    exposure_component: float = 0.0
    cve_id: str | None = None
    cwe_id: str | None = None
    mitre_technique_ids: list[str] = Field(default_factory=list)
    title: str = ""
    remediation_priority: int = 0  # 1 = highest


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

class RemediationItem(BaseModel):
    """Remediation recommendation for a finding."""

    remediation_id: str
    finding_id: str
    asset_id: str
    title: str
    description: str
    effort_estimate: str = "medium"  # low | medium | high
    fix_type: str = "patch"  # patch | config | upgrade | workaround
    priority: int = 0
    reference_urls: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportArtifact(BaseModel):
    """Generated VAPT report artifact."""

    report_id: str
    report_type: str  # executive | technical | compliance
    engagement_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    summary: str = ""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    content: dict[str, Any] = Field(default_factory=dict)
