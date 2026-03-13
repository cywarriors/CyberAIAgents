"""Domain models for the Identity & Access Monitoring Agent (SRS-06)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ── Enums ──────────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuthOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    MFA_DENIED = "mfa_denied"
    MFA_TIMEOUT = "mfa_timeout"
    LOCKED_OUT = "locked_out"


class MFAMethod(str, Enum):
    PUSH = "push"
    TOTP = "totp"
    SMS = "sms"
    FIDO2 = "fido2"
    EMAIL = "email"
    NONE = "none"


class PrivilegeAction(str, Enum):
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    GROUP_ADDED = "group_added"
    GROUP_REMOVED = "group_removed"


class RecommendedControl(str, Enum):
    STEP_UP_MFA = "step_up_mfa"
    SESSION_KILL = "session_kill"
    TEMPORARY_LOCKOUT = "temporary_lockout"
    PASSWORD_RESET = "password_reset"
    ACCESS_REVIEW = "access_review"
    MONITOR = "monitor"
    NO_ACTION = "no_action"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FeedbackVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_TUNING = "needs_tuning"


# ── Data classes ───────────────────────────────────────────────────


@dataclass
class AuthEvent:
    """Single authentication event from IdP / MFA."""

    event_id: str = ""
    user_id: str = ""
    username: str = ""
    outcome: str = "success"
    mfa_method: str = "none"
    mfa_passed: bool = True
    source_ip: str = ""
    geo_latitude: float = 0.0
    geo_longitude: float = 0.0
    geo_city: str = ""
    geo_country: str = ""
    device_id: str = ""
    device_type: str = ""
    user_agent: str = ""
    application: str = ""
    timestamp: str = ""


@dataclass
class RoleChangeEvent:
    """Privilege / role change event from IAM."""

    event_id: str = ""
    user_id: str = ""
    username: str = ""
    action: str = "role_assigned"
    role_name: str = ""
    role_risk_level: str = "low"
    changed_by: str = ""
    justification: str = ""
    timestamp: str = ""


@dataclass
class SessionProfile:
    """Aggregated session / behavioural profile for a user."""

    user_id: str = ""
    username: str = ""
    login_count_24h: int = 0
    failed_login_count_24h: int = 0
    mfa_challenge_count_1h: int = 0
    mfa_denied_count_1h: int = 0
    unique_ips_24h: int = 0
    unique_devices_24h: int = 0
    is_impossible_travel: bool = False
    travel_speed_kmh: float = 0.0
    is_new_device: bool = False
    is_new_location: bool = False
    is_off_hours: bool = False
    usual_login_hours: str = "08:00-18:00"
    department: str = ""
    is_vip: bool = False


@dataclass
class EntitlementRecord:
    """Current entitlement snapshot for SoD analysis."""

    user_id: str = ""
    username: str = ""
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    is_privileged: bool = False
    last_access_review: str = ""
    department: str = ""


@dataclass
class RiskIndicator:
    """Individual risk signal contributing to identity risk score."""

    indicator_type: str = ""
    description: str = ""
    severity: str = "low"
    confidence: float = 0.0
    evidence: str = ""
    source_event_id: str = ""
    user_id: str = ""
    timestamp: str = ""


@dataclass
class IdentityRiskScore:
    """Computed identity risk score for a user."""

    user_id: str = ""
    username: str = ""
    risk_score: float = 0.0
    risk_level: str = "low"
    indicators: list[dict[str, Any]] = field(default_factory=list)
    components: dict[str, float] = field(default_factory=dict)
    explanation: str = ""
    recommended_control: str = "no_action"
    confidence: float = 0.0
    timestamp: str = ""


@dataclass
class SoDViolation:
    """Segregation-of-Duties violation."""

    user_id: str = ""
    username: str = ""
    conflicting_roles: list[str] = field(default_factory=list)
    conflicting_permissions: list[str] = field(default_factory=list)
    rule_id: str = ""
    rule_name: str = ""
    severity: str = "high"
    recommendation: str = ""


@dataclass
class ControlRecommendation:
    """Step-up auth or access suspension recommendation (FR-06)."""

    user_id: str = ""
    username: str = ""
    control: str = "no_action"
    reason: str = ""
    risk_score: float = 0.0
    risk_level: str = "low"
    auto_enforce: bool = False
    requires_approval: bool = True
    timestamp: str = ""


@dataclass
class IdentityAlert:
    """SOC / ITSM alert."""

    alert_id: str = ""
    user_id: str = ""
    username: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    risk_score: float = 0.0
    indicators: list[dict[str, Any]] = field(default_factory=list)
    recommended_control: str = "no_action"
    status: str = "open"
    created_at: str = ""
    ticket_id: str = ""


@dataclass
class FeedbackItem:
    """Analyst adjudication feedback (FR-10)."""

    alert_id: str = ""
    analyst_id: str = ""
    verdict: str = "true_positive"
    notes: str = ""
    policy_change: str = ""
    timestamp: str = ""
