"""Pydantic schemas for the Identity & Access Monitoring Agent BFF API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RiskScoreResponse(BaseModel):
    user_id: str
    username: str = ""
    risk_score: float = 0.0
    risk_level: str = "low"
    indicators: list[dict] = Field(default_factory=list)
    components: dict[str, float] = Field(default_factory=dict)
    explanation: str = ""
    recommended_control: str = "no_action"
    confidence: float = 0.0
    timestamp: str = ""


class AlertResponse(BaseModel):
    alert_id: str
    user_id: str = ""
    username: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    risk_score: float = 0.0
    indicators: list[dict] = Field(default_factory=list)
    recommended_control: str = "no_action"
    status: str = "open"
    created_at: str = ""
    ticket_id: str = ""


class SoDViolationResponse(BaseModel):
    user_id: str
    username: str = ""
    conflicting_roles: list[str] = Field(default_factory=list)
    conflicting_permissions: list[str] = Field(default_factory=list)
    rule_id: str = ""
    rule_name: str = ""
    severity: str = "high"
    recommendation: str = ""


class RecommendationResponse(BaseModel):
    user_id: str
    username: str = ""
    control: str = "no_action"
    reason: str = ""
    risk_score: float = 0.0
    risk_level: str = "low"
    auto_enforce: bool = False
    requires_approval: bool = True
    timestamp: str = ""


class UserRiskResponse(BaseModel):
    user_id: str
    username: str = ""
    department: str = ""
    risk_score: float = 0.0
    risk_level: str = "low"
    active_alerts: int = 0
    sod_violations: int = 0
    last_login: str = ""
    is_vip: bool = False


class DashboardSummaryResponse(BaseModel):
    total_events_processed: int = 0
    critical_risk_users: int = 0
    high_risk_users: int = 0
    medium_risk_users: int = 0
    low_risk_users: int = 0
    total_alerts: int = 0
    open_alerts: int = 0
    sod_violations: int = 0
    impossible_travel_detections: int = 0
    mfa_fatigue_detections: int = 0
    brute_force_detections: int = 0
    privilege_escalation_detections: int = 0
    false_positive_rate: float = 0.0
    mean_risk_score: float = 0.0
    top_risky_users: list[dict] = Field(default_factory=list)
    risk_trend: list[dict] = Field(default_factory=list)


class FeedbackRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, max_length=128)
    verdict: str = Field(..., pattern=r"^(true_positive|false_positive|needs_tuning)$")
    notes: str = Field(default="", max_length=2000)


class ProcessEventsRequest(BaseModel):
    auth_events: list[dict] = Field(default_factory=list, max_length=500)
    role_changes: list[dict] = Field(default_factory=list, max_length=100)
