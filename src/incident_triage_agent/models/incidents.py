"""Alert and incident models for the Incident Triage Agent."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Priority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class IncidentClassification(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    CREDENTIAL_ABUSE = "credential_abuse"
    INSIDER_THREAT = "insider_threat"
    DATA_EXFILTRATION = "data_exfiltration"
    RANSOMWARE = "ransomware"
    DENIAL_OF_SERVICE = "denial_of_service"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    UNKNOWN = "unknown"


class FeedbackVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_TUNING = "needs_tuning"
    RECLASSIFIED = "reclassified"


class EnrichmentQuality(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    STALE = "stale"
    MISSING = "missing"


# --- Incoming alert ---


class IncomingAlert(BaseModel):
    """Alert ingested from SIEM or EDR systems (FR-01)."""

    alert_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str  # "siem" | "edr"
    severity: Severity = Severity.MEDIUM
    confidence: int = Field(default=50, ge=0, le=100)
    mitre_technique_ids: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)
    matched_event_ids: list[str] = Field(default_factory=list)
    description: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


# --- Entity enrichment ---


class EntityProfile(BaseModel):
    """Enriched entity context (FR-03)."""

    entity_id: str
    entity_type: str  # "user" | "host" | "ip"
    # User context
    user_name: str | None = None
    user_role: str | None = None
    user_department: str | None = None
    is_privileged: bool = False
    # Host context
    host_name: str | None = None
    os_type: str | None = None
    asset_criticality: str = "low"  # "critical" | "high" | "medium" | "low"
    asset_owner: str | None = None
    # Geolocation
    geo_country: str | None = None
    geo_city: str | None = None
    # Vulnerability context
    open_vuln_count: int = 0
    critical_vuln_count: int = 0
    # Quality indicator (FR-12)
    enrichment_quality: EnrichmentQuality = EnrichmentQuality.COMPLETE
    enrichment_timestamp: datetime | None = None


# --- Correlation ---


class CorrelationGroup(BaseModel):
    """Group of correlated alerts forming an incident (FR-02)."""

    group_id: str
    alert_ids: list[str] = Field(default_factory=list)
    shared_entities: list[str] = Field(default_factory=list)
    attack_chain: list[str] = Field(default_factory=list)  # ordered MITRE tactics
    time_span_seconds: float = 0.0
    correlation_reason: str = ""


# --- Priority scoring ---


class PriorityScore(BaseModel):
    """Computed incident priority with component breakdown (FR-04)."""

    priority: Priority
    raw_score: float = Field(..., ge=0.0, le=100.0)
    confidence: int = Field(..., ge=0, le=100)
    components: dict[str, float] = Field(default_factory=dict)
    explanation: str = ""


# --- Recommended actions ---


class RecommendedAction(BaseModel):
    """Investigative next action (FR-07)."""

    action_id: str
    title: str
    description: str
    priority_order: int = 0
    action_type: str = "investigate"  # "investigate" | "contain" | "escalate" | "notify"
    target_entity: str | None = None


# --- Incident (output) ---


class TriagedIncident(BaseModel):
    """Final triaged incident delivered to SOC analyst (FR-06)."""

    incident_id: str
    case_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    priority: Priority
    classification: IncidentClassification
    severity: Severity
    confidence: int = Field(default=50, ge=0, le=100)
    triage_summary: str = ""
    alert_ids: list[str] = Field(default_factory=list)
    entity_profiles: list[dict[str, Any]] = Field(default_factory=list)
    correlation_groups: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    mitre_technique_ids: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    published_to: list[str] = Field(default_factory=list)


# --- Analyst feedback ---


class FeedbackItem(BaseModel):
    """Analyst feedback on a triaged incident (FR-09)."""

    incident_id: str
    analyst_id: str
    verdict: FeedbackVerdict
    corrected_priority: Priority | None = None
    corrected_classification: IncidentClassification | None = None
    comment: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
