"""Pydantic schemas for the Threat Detection BFF API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────

class Severity(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    info = "Info"


class AlertStatus(str, Enum):
    new = "new"
    investigating = "investigating"
    escalated = "escalated"
    resolved = "resolved"
    dismissed = "dismissed"


class FeedbackVerdict(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    needs_tuning = "needs_tuning"


class RuleStatus(str, Enum):
    draft = "draft"
    testing = "testing"
    production = "production"
    deprecated = "deprecated"


# ── Alert schemas ─────────────────────────────────────────────────

class AlertResponse(BaseModel):
    alert_id: str
    timestamp: str
    severity: str
    confidence: int
    mitre_technique_ids: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    source_type: str = ""
    entity_ids: list[str] = Field(default_factory=list)
    matched_event_ids: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    description: str = ""
    status: str = "new"
    analyst_notes: str = ""
    related_alert_ids: list[str] = Field(default_factory=list)


class AlertUpdate(BaseModel):
    status: str | None = None
    analyst_notes: str | None = None


class AlertFeedback(BaseModel):
    analyst_id: str
    verdict: FeedbackVerdict
    comment: str = ""


class PaginatedAlerts(BaseModel):
    items: list[AlertResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ── Rule schemas ──────────────────────────────────────────────────

class RuleResponse(BaseModel):
    rule_id: str
    rule_name: str
    mitre_technique_id: str = ""
    mitre_tactic: str = ""
    severity: str = "Medium"
    description: str = ""
    logic: str = ""
    status: str = "draft"
    created_at: str = ""
    updated_at: str = ""
    hit_count: int = 0


class RuleCreate(BaseModel):
    rule_name: str
    mitre_technique_id: str = ""
    mitre_tactic: str = ""
    severity: str = "Medium"
    description: str = ""
    logic: str = ""


class RuleUpdate(BaseModel):
    rule_name: str | None = None
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    severity: str | None = None
    description: str | None = None
    logic: str | None = None
    status: str | None = None


class RuleTestRequest(BaseModel):
    test_events: list[dict[str, Any]] = Field(default_factory=list)


class RuleTestResult(BaseModel):
    rule_id: str
    events_tested: int
    matches_found: int
    matched_event_ids: list[str] = Field(default_factory=list)


# ── Anomaly schemas ───────────────────────────────────────────────

class AnomalyResponse(BaseModel):
    anomaly_id: str
    timestamp: str
    anomaly_type: str
    anomaly_score: float
    baseline_value: float
    observed_value: float
    entity_type: str
    entity_id: str
    description: str = ""


# ── Coverage schemas ──────────────────────────────────────────────

class TechniqueCoverage(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    rule_count: int = 0
    alert_count: int = 0
    covered: bool = False


class CoverageResponse(BaseModel):
    total_techniques: int
    covered_techniques: int
    coverage_percentage: float
    techniques: list[TechniqueCoverage]


# ── Dashboard schemas ─────────────────────────────────────────────

class DashboardMetrics(BaseModel):
    total_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    info_alerts: int = 0
    active_anomalies: int = 0
    rules_deployed: int = 0
    mttd_seconds: float = 0.0
    pipeline_throughput_eps: float = 0.0
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    top_triggered_rules: list[dict[str, Any]] = Field(default_factory=list)
    alert_volume_timeline: list[dict[str, Any]] = Field(default_factory=list)


# ── Pipeline Health schemas ───────────────────────────────────────

class NodeHealth(BaseModel):
    node_name: str
    status: str = "healthy"
    events_processed: int = 0
    errors: int = 0
    avg_latency_ms: float = 0.0
    last_heartbeat: str = ""


class PipelineHealthResponse(BaseModel):
    status: str = "healthy"
    uptime_seconds: float = 0.0
    nodes: list[NodeHealth] = Field(default_factory=list)
    kafka_connected: bool = False
    redis_connected: bool = False
    postgres_connected: bool = False
    queue_depth: int = 0


# ── Tuning schemas ────────────────────────────────────────────────

class TuningMetrics(BaseModel):
    total_feedback: int = 0
    true_positive_rate: float = 0.0
    false_positive_rate: float = 0.0
    needs_tuning_count: int = 0
    rule_hit_rates: list[dict[str, Any]] = Field(default_factory=list)
    threshold_recommendations: list[dict[str, Any]] = Field(default_factory=list)


# ── Generic ───────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str
