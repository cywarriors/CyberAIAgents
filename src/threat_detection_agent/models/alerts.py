"""Alert and detection result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FeedbackVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_TUNING = "needs_tuning"


# --- Detection results ---


class RuleMatch(BaseModel):
    """Result from the rule-based detection engine."""

    rule_id: str
    rule_name: str
    mitre_technique_id: str
    mitre_tactic: str
    matched_event_ids: list[str]
    severity: Severity
    description: str
    raw_evidence: list[dict[str, Any]] = Field(default_factory=list)


class AnomalyResult(BaseModel):
    """Result from the ML behaviour anomaly model."""

    model_id: str
    anomaly_type: str  # e.g. "user_login_anomaly", "network_traffic_spike"
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    baseline_value: float
    observed_value: float
    entity_type: str  # user | host | network
    entity_id: str
    matched_event_ids: list[str]
    description: str


# --- Alert lifecycle ---


class AlertCandidate(BaseModel):
    """Intermediate alert before deduplication."""

    candidate_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: Severity
    confidence: int = Field(..., ge=0, le=100)
    mitre_technique_ids: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    source_type: str  # "rule" | "anomaly" | "hybrid"
    entity_ids: list[str] = Field(default_factory=list)
    matched_event_ids: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    description: str = ""


class Alert(BaseModel):
    """Final deduplicated alert delivered to SOC."""

    alert_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: Severity
    confidence: int = Field(..., ge=0, le=100)
    mitre_technique_ids: list[str]
    mitre_tactics: list[str]
    source_type: str
    entity_ids: list[str]
    matched_event_ids: list[str]
    evidence: list[dict[str, Any]]
    description: str
    published_to: list[str] = Field(default_factory=list)


class FeedbackItem(BaseModel):
    """Analyst feedback on a published alert."""

    alert_id: str
    analyst_id: str
    verdict: FeedbackVerdict
    comment: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
