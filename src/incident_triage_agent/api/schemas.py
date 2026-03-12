"""Pydantic schemas for the Incident Triage BFF API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────

class Priority(str, Enum):
    p1 = "P1"
    p2 = "P2"
    p3 = "P3"
    p4 = "P4"


class Severity(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    info = "Info"


class IncidentStatus(str, Enum):
    new = "new"
    triaging = "triaging"
    escalated = "escalated"
    assigned = "assigned"
    resolved = "resolved"
    false_positive = "false_positive"


class FeedbackVerdict(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    needs_tuning = "needs_tuning"
    reclassified = "reclassified"


# ── Incident schemas ──────────────────────────────────────────────

class IncidentResponse(BaseModel):
    incident_id: str
    case_id: str = ""
    timestamp: str
    priority: str
    classification: str = "unknown"
    severity: str = "Medium"
    confidence: int = 50
    triage_summary: str = ""
    status: str = "new"
    assigned_analyst: str = ""
    sla_remaining_seconds: int = 0
    alert_ids: list[str] = Field(default_factory=list)
    entity_profiles: list[dict[str, Any]] = Field(default_factory=list)
    correlation_groups: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    mitre_technique_ids: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    analyst_notes: str = ""


class IncidentUpdate(BaseModel):
    status: str | None = None
    assigned_analyst: str | None = None
    priority: str | None = None
    analyst_notes: str | None = None


class IncidentFeedback(BaseModel):
    analyst_id: str
    verdict: FeedbackVerdict
    corrected_priority: str | None = None
    corrected_classification: str | None = None
    comment: str = ""


class PaginatedIncidents(BaseModel):
    items: list[IncidentResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ── Correlation schemas ───────────────────────────────────────────

class CorrelationNode(BaseModel):
    node_id: str
    node_type: str  # "alert" | "incident"
    label: str
    severity: str = "Medium"


class CorrelationEdge(BaseModel):
    source: str
    target: str
    method: str  # "temporal" | "entity" | "technique"


class CorrelationGraph(BaseModel):
    nodes: list[CorrelationNode] = Field(default_factory=list)
    edges: list[CorrelationEdge] = Field(default_factory=list)


# ── Playbook schemas ─────────────────────────────────────────────

class PlaybookRecommendation(BaseModel):
    playbook_id: str
    name: str
    description: str
    confidence: float = 0.0
    steps: list[str] = Field(default_factory=list)
    action_type: str = "investigate"


# ── Dashboard schemas ─────────────────────────────────────────────

class DashboardSummary(BaseModel):
    open_incidents: int = 0
    p1_count: int = 0
    p2_count: int = 0
    p3_count: int = 0
    p4_count: int = 0
    mttt_seconds: float = 0.0
    sla_compliance_pct: float = 100.0
    incidents_today: int = 0
    escalation_rate: float = 0.0
    priority_breakdown: dict[str, int] = Field(default_factory=dict)
    top_categories: list[dict[str, Any]] = Field(default_factory=list)


# ── Analyst workload schemas ──────────────────────────────────────

class AnalystWorkload(BaseModel):
    analyst_id: str
    analyst_name: str
    open_incidents: int = 0
    avg_handling_time_seconds: float = 0.0
    resolved_today: int = 0


# ── Triage metrics schemas ───────────────────────────────────────

class TriageMetrics(BaseModel):
    total_triaged: int = 0
    mttt_trend: list[dict[str, Any]] = Field(default_factory=list)
    priority_accuracy: float = 0.0
    escalation_rate: float = 0.0
    true_positive_rate: float = 0.0
    false_positive_rate: float = 0.0
    category_distribution: dict[str, int] = Field(default_factory=dict)


# ── System health ─────────────────────────────────────────────────

class SystemHealth(BaseModel):
    status: str = "healthy"
    uptime_seconds: float = 0.0
    pipeline_nodes: list[dict[str, Any]] = Field(default_factory=list)
    kafka_connected: bool = False
    redis_connected: bool = False
    postgres_connected: bool = False


# ── Generic ───────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str
