"""Pydantic schemas for the VAPT BFF API layer (request / response models)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EngagementStatus(str, Enum):
    draft = "draft"
    approved = "approved"
    in_progress = "in_progress"
    completed = "completed"
    archived = "archived"


class SeverityLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ExploitRisk(str, Enum):
    safe = "safe"
    moderate = "moderate"
    destructive = "destructive"


class ReportType(str, Enum):
    executive = "executive"
    technical = "technical"
    compliance = "compliance"
    custom = "custom"


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------

class RoEPayload(BaseModel):
    scope_ips: list[str] = Field(default_factory=list)
    scope_domains: list[str] = Field(default_factory=list)
    scope_cloud_accounts: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    allow_destructive: bool = False
    start_time: datetime | None = None
    end_time: datetime | None = None


class EngagementCreate(BaseModel):
    name: str
    description: str = ""
    roe: RoEPayload
    scheduled_start: datetime | None = None


class EngagementUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: EngagementStatus | None = None
    roe: RoEPayload | None = None


class EngagementResponse(BaseModel):
    id: str
    name: str
    description: str
    status: EngagementStatus
    roe: RoEPayload
    created_at: datetime
    updated_at: datetime
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class FindingFilter(BaseModel):
    severity: list[SeverityLevel] | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    asset_id: str | None = None
    engagement_id: str | None = None
    status: str | None = None
    search: str | None = None
    page: int = 1
    page_size: int = 25
    sort_by: str = "composite_score"
    sort_order: str = "desc"


class FindingResponse(BaseModel):
    id: str
    engagement_id: str
    asset_id: str
    title: str
    severity: SeverityLevel
    cve_id: str | None = None
    cwe_id: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    composite_score: float = 0
    in_kev: bool = False
    status: str = "open"
    matched_rules: list[str] = Field(default_factory=list)
    remediation: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class FindingUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None


class PaginatedFindings(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

class ScanCreate(BaseModel):
    engagement_id: str
    targets: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=lambda: ["nuclei", "nessus", "zap"])


class ScanResponse(BaseModel):
    id: str
    engagement_id: str
    status: str = "pending"
    progress: float = 0.0
    targets: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list)
    findings_count: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None


# ---------------------------------------------------------------------------
# Attack Paths
# ---------------------------------------------------------------------------

class AttackPathStep(BaseModel):
    step: int
    asset_id: str
    technique: str
    mitre_technique_id: str | None = None


class AttackPathResponse(BaseModel):
    id: str
    engagement_id: str
    steps: list[AttackPathStep]
    composite_risk: float
    asset_count: int


# ---------------------------------------------------------------------------
# Exploits
# ---------------------------------------------------------------------------

class ExploitModule(BaseModel):
    id: str
    name: str
    description: str = ""
    risk_level: ExploitRisk
    cve_id: str | None = None
    mitre_technique_id: str | None = None


class ExploitExecuteRequest(BaseModel):
    target_asset_id: str
    finding_id: str
    approval_token: str | None = None


class ExploitExecuteResponse(BaseModel):
    execution_id: str
    module_id: str
    target_asset_id: str
    finding_id: str
    status: str = "pending"
    success: bool | None = None
    rollback_success: bool | None = None
    started_at: datetime | None = None


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class ReportCreate(BaseModel):
    engagement_id: str
    report_type: ReportType = ReportType.executive
    sections: list[str] | None = None
    include_findings: bool = True


class ReportResponse(BaseModel):
    id: str
    engagement_id: str
    report_type: ReportType
    status: str = "pending"
    generated_at: datetime | None = None
    download_url: str | None = None
    content: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class DashboardSummary(BaseModel):
    active_engagements: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    assets_discovered: int = 0
    attack_paths_found: int = 0
    exploits_validated: int = 0
    reports_generated: int = 0
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    risk_trend: list[dict[str, Any]] = Field(default_factory=list)
    top_vulnerable_assets: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

class ComplianceScheduleCreate(BaseModel):
    engagement_id: str
    framework: str
    frequency: str = "quarterly"
    next_due: datetime | None = None


class ComplianceScheduleResponse(BaseModel):
    id: str
    engagement_id: str
    framework: str
    frequency: str
    next_due: datetime | None = None
    last_completed: datetime | None = None
    status: str = "on_track"


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

class SystemHealthResponse(BaseModel):
    status: str = "healthy"
    uptime_seconds: float = 0
    scanner_engines: dict[str, str] = Field(default_factory=dict)
    kafka_connected: bool = False
    redis_connected: bool = False
    postgres_connected: bool = False


# ---------------------------------------------------------------------------
# Generic
# ---------------------------------------------------------------------------

class MessageResponse(BaseModel):
    message: str
    id: str | None = None
