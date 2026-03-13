"""Domain models for the Phishing Defense Agent."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Enums ────────────────────────────────────────────────────────


class Verdict(str, enum.Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class VerdictAction(str, enum.Enum):
    ALLOW = "allow"
    WARN = "warn"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class AuthStatus(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    SOFT_FAIL = "soft_fail"
    NEUTRAL = "neutral"


class ContentThreatType(str, enum.Enum):
    URGENCY = "urgency"
    IMPERSONATION = "impersonation"
    CREDENTIAL_HARVEST = "credential_harvest"
    FINANCIAL_FRAUD = "financial_fraud"
    MALWARE_DELIVERY = "malware_delivery"
    BEC = "business_email_compromise"
    SOCIAL_ENGINEERING = "social_engineering"


class SandboxVerdict(str, enum.Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    TIMEOUT = "timeout"
    ERROR = "error"


class QuarantineStatus(str, enum.Enum):
    QUARANTINED = "quarantined"
    RELEASED = "released"
    DELETED = "deleted"
    PENDING_REVIEW = "pending_review"


class FeedbackVerdict(str, enum.Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_TUNING = "needs_tuning"


# ── Data Classes ─────────────────────────────────────────────────


@dataclass
class EmailMetadata:
    """Parsed email metadata and content."""

    message_id: str = ""
    subject: str = ""
    sender_address: str = ""
    sender_display_name: str = ""
    reply_to: str = ""
    return_path: str = ""
    recipient_addresses: list[str] = field(default_factory=list)
    cc_addresses: list[str] = field(default_factory=list)
    received_timestamp: datetime = field(default_factory=_utcnow)
    headers: dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    body_html: str = ""
    urls: list[str] = field(default_factory=list)
    attachment_names: list[str] = field(default_factory=list)
    attachment_hashes: list[str] = field(default_factory=list)
    attachment_sizes: list[int] = field(default_factory=list)
    is_internal: bool = False
    sender_domain: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthResult:
    """SPF / DKIM / DMARC authentication results."""

    spf_status: AuthStatus = AuthStatus.NONE
    dkim_status: AuthStatus = AuthStatus.NONE
    dmarc_status: AuthStatus = AuthStatus.NONE
    spf_domain: str = ""
    dkim_domain: str = ""
    dmarc_domain: str = ""
    is_lookalike_domain: bool = False
    lookalike_target: str = ""
    domain_age_days: int = -1
    sender_reputation_score: float = 0.0
    auth_summary: str = ""


@dataclass
class ContentSignal:
    """NLP-detected content signal."""

    signal_type: ContentThreatType = ContentThreatType.SOCIAL_ENGINEERING
    confidence: float = 0.0
    evidence: str = ""
    matched_patterns: list[str] = field(default_factory=list)


@dataclass
class URLAnalysis:
    """URL reputation and redirect analysis."""

    url: str = ""
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    domain: str = ""
    domain_age_days: int = -1
    is_known_phishing: bool = False
    reputation_score: float = 0.0
    is_shortened: bool = False
    is_data_uri: bool = False
    sandbox_verdict: SandboxVerdict = SandboxVerdict.CLEAN
    threat_categories: list[str] = field(default_factory=list)


@dataclass
class AttachmentAnalysis:
    """Attachment detonation result."""

    filename: str = ""
    file_hash: str = ""
    file_size: int = 0
    file_type: str = ""
    sandbox_verdict: SandboxVerdict = SandboxVerdict.CLEAN
    malware_family: str = ""
    behavioral_indicators: list[str] = field(default_factory=list)
    iocs_extracted: list[str] = field(default_factory=list)


@dataclass
class SandboxResult:
    """Combined sandbox detonation result."""

    url_results: list[URLAnalysis] = field(default_factory=list)
    attachment_results: list[AttachmentAnalysis] = field(default_factory=list)
    overall_verdict: SandboxVerdict = SandboxVerdict.CLEAN
    detonation_duration_seconds: float = 0.0


@dataclass
class IOCEntry:
    """Indicator of Compromise extracted from a phishing email."""

    ioc_type: str = ""  # url, domain, ip, file_hash, email
    ioc_value: str = ""
    source_message_id: str = ""
    confidence: float = 0.0
    first_seen: datetime = field(default_factory=_utcnow)
    tags: list[str] = field(default_factory=list)


@dataclass
class PhishingVerdict:
    """Final verdict for a single email."""

    message_id: str = ""
    risk_score: float = 0.0
    verdict: Verdict = Verdict.CLEAN
    action: VerdictAction = VerdictAction.ALLOW
    confidence: float = 0.0
    auth_result: AuthResult = field(default_factory=AuthResult)
    content_signals: list[ContentSignal] = field(default_factory=list)
    sandbox_result: SandboxResult | None = None
    iocs: list[IOCEntry] = field(default_factory=list)
    explanation: str = ""
    processed_at: datetime = field(default_factory=_utcnow)
    campaign_id: str = ""
    score_components: dict[str, float] = field(default_factory=dict)


@dataclass
class QuarantineEntry:
    """An email held in quarantine."""

    quarantine_id: str = ""
    message_id: str = ""
    email_metadata: EmailMetadata = field(default_factory=EmailMetadata)
    verdict: PhishingVerdict = field(default_factory=PhishingVerdict)
    status: QuarantineStatus = QuarantineStatus.QUARANTINED
    quarantined_at: datetime = field(default_factory=_utcnow)
    reviewed_by: str = ""
    reviewed_at: datetime | None = None
    release_justification: str = ""


@dataclass
class CampaignCluster:
    """A group of related phishing emails forming a campaign."""

    campaign_id: str = ""
    campaign_name: str = ""
    first_seen: datetime = field(default_factory=_utcnow)
    last_seen: datetime = field(default_factory=_utcnow)
    email_count: int = 0
    targeted_users: list[str] = field(default_factory=list)
    targeted_departments: list[str] = field(default_factory=list)
    iocs: list[IOCEntry] = field(default_factory=list)
    sender_domains: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    severity: str = "medium"


@dataclass
class UserReport:
    """A user-reported suspicious email."""

    report_id: str = ""
    reporter_email: str = ""
    reported_message_id: str = ""
    report_timestamp: datetime = field(default_factory=_utcnow)
    reporter_comment: str = ""
    analyst_verdict: FeedbackVerdict | None = None
    analyst_notes: str = ""
    processed: bool = False


@dataclass
class AwarenessMetrics:
    """User awareness dashboard metrics."""

    total_reports: int = 0
    true_positive_reports: int = 0
    false_positive_reports: int = 0
    click_through_rate: float = 0.0
    report_rate: float = 0.0
    top_reporters: list[dict[str, Any]] = field(default_factory=list)
    department_stats: list[dict[str, Any]] = field(default_factory=list)
    training_completion_rate: float = 0.0


@dataclass
class FeedbackItem:
    """Analyst feedback on a verdict for model tuning."""

    feedback_id: str = ""
    message_id: str = ""
    analyst_id: str = ""
    original_verdict: Verdict = Verdict.CLEAN
    corrected_verdict: FeedbackVerdict = FeedbackVerdict.TRUE_POSITIVE
    comment: str = ""
    submitted_at: datetime = field(default_factory=_utcnow)
