"""Pydantic schemas for the Phishing Defense Agent BFF API."""

from __future__ import annotations

from pydantic import BaseModel, Field


# ── Enums as string literals ──────────────────────────────────


class VerdictResponse(BaseModel):
    message_id: str
    subject: str = ""
    sender_address: str = ""
    recipient_addresses: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    verdict: str = "clean"
    action: str = "allow"
    confidence: float = 0.0
    explanation: str = ""
    components: dict[str, float] = Field(default_factory=dict)
    processed_at: str = ""
    campaign_id: str = ""


class QuarantineItemResponse(BaseModel):
    quarantine_id: str
    message_id: str
    subject: str = ""
    sender_address: str = ""
    recipient_addresses: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    verdict: str = "malicious"
    confidence: float = 0.0
    status: str = "quarantined"
    quarantined_at: str = ""
    reviewed_by: str = ""
    explanation: str = ""


class QuarantineReleaseRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, max_length=128)
    justification: str = Field(..., min_length=10, max_length=2000)


class QuarantineDeleteRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(default="confirmed_phishing", max_length=500)


class CampaignResponse(BaseModel):
    campaign_id: str
    campaign_name: str = ""
    first_seen: str = ""
    last_seen: str = ""
    email_count: int = 0
    targeted_users: list[str] = Field(default_factory=list)
    targeted_departments: list[str] = Field(default_factory=list)
    sender_domains: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    severity: str = "medium"
    ioc_count: int = 0


class ReportedEmailResponse(BaseModel):
    report_id: str
    reporter_email: str = ""
    reported_message_id: str = ""
    report_timestamp: str = ""
    reporter_comment: str = ""
    analyst_verdict: str | None = None
    analyst_notes: str = ""
    processed: bool = False


class ReportedEmailReviewRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, max_length=128)
    verdict: str = Field(..., pattern=r"^(true_positive|false_positive|needs_tuning)$")
    notes: str = Field(default="", max_length=2000)


class AwarenessMetricsResponse(BaseModel):
    total_reports: int = 0
    true_positive_reports: int = 0
    false_positive_reports: int = 0
    click_through_rate: float = 0.0
    report_rate: float = 0.0
    top_reporters: list[dict] = Field(default_factory=list)
    department_stats: list[dict] = Field(default_factory=list)
    training_completion_rate: float = 0.0


class DashboardSummaryResponse(BaseModel):
    total_processed: int = 0
    clean_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    quarantine_count: int = 0
    blocked_count: int = 0
    warned_count: int = 0
    allowed_count: int = 0
    false_positive_rate: float = 0.0
    detection_rate: float = 0.0
    mean_verdict_latency_ms: float = 0.0
    active_campaigns: int = 0
    iocs_extracted: int = 0
    user_reports_today: int = 0
    top_targeted_departments: list[dict] = Field(default_factory=list)
    verdict_trend: list[dict] = Field(default_factory=list)


class ProcessEmailsRequest(BaseModel):
    emails: list[dict] = Field(..., min_length=1, max_length=100)
