"""Pydantic request / response schemas for the BFF API."""

from __future__ import annotations

import re
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ── Shared ───────────────────────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    items: list[Any] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 20
    pages: int = 1


# ── IOC ──────────────────────────────────────────────────────────────────────

class IOCResponse(BaseModel):
    ioc_id: str
    ioc_type: str
    value: str
    sources: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    lifecycle: str = "new"
    confidence: float = 0.0
    relevance: float = 0.0
    tlp: str = "TLP:GREEN"
    actor: str = ""
    campaign: str = ""


class IOCListResponse(PaginatedResponse):
    items: list[IOCResponse] = Field(default_factory=list)


class IOCRelationshipResponse(BaseModel):
    ioc_id: str
    related_iocs: list[dict[str, Any]] = Field(default_factory=list)
    related_actors: list[dict[str, Any]] = Field(default_factory=list)
    related_campaigns: list[dict[str, Any]] = Field(default_factory=list)


class IOCExportRequest(BaseModel):
    format: str = "stix"  # stix | csv
    ioc_ids: list[str] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        if v not in ("stix", "csv"):
            raise ValueError("format must be 'stix' or 'csv'")
        return v


class IOCLifecycleUpdate(BaseModel):
    lifecycle: str
    reason: str = ""

    @field_validator("lifecycle")
    @classmethod
    def validate_lifecycle(cls, v: str) -> str:
        allowed = {"new", "active", "deprecated", "revoked"}
        if v not in allowed:
            raise ValueError(f"lifecycle must be one of {allowed}")
        return v


# ── Brief ────────────────────────────────────────────────────────────────────

class BriefResponse(BaseModel):
    brief_id: str
    level: str
    title: str
    executive_summary: str = ""
    technical_analysis: str = ""
    ioc_appendix: list[dict[str, Any]] = Field(default_factory=list)
    attck_mapping: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    created: str = ""
    tlp: str = "TLP:GREEN"


class BriefListResponse(PaginatedResponse):
    items: list[BriefResponse] = Field(default_factory=list)


# ── Actor ────────────────────────────────────────────────────────────────────

class ActorResponse(BaseModel):
    actor_id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    targeted_sectors: list[str] = Field(default_factory=list)
    targeted_regions: list[str] = Field(default_factory=list)
    ttps: list[dict[str, Any]] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    associated_iocs: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class ActorListResponse(PaginatedResponse):
    items: list[ActorResponse] = Field(default_factory=list)


# ── Feed ─────────────────────────────────────────────────────────────────────

class FeedSourceResponse(BaseModel):
    feed_id: str
    name: str
    source_type: str
    url: str = ""
    enabled: bool = True
    last_poll: str = ""
    success_rate: float = 1.0
    ioc_yield: int = 0
    quality_score: float = 50.0
    false_positive_rate: float = 0.0


class FeedCreateRequest(BaseModel):
    name: str
    source_type: str
    url: str = ""
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[\w\s\-\.]{1,100}$", v):
            raise ValueError("Feed name contains invalid characters")
        return v

    @field_validator("source_type")
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        allowed = {"osint", "commercial", "isac", "internal"}
        if v not in allowed:
            raise ValueError(f"source_type must be one of {allowed}")
        return v


class FeedUpdateRequest(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    enabled: Optional[bool] = None


class FeedHealthResponse(BaseModel):
    feed_id: str
    name: str
    status: str = "healthy"
    last_poll: str = ""
    success_rate: float = 1.0
    ioc_yield: int = 0
    error_message: Optional[str] = None


# ── Dashboard ────────────────────────────────────────────────────────────────

class DashboardMetricsResponse(BaseModel):
    total_iocs: int = 0
    active_iocs: int = 0
    feeds_healthy: int = 0
    feeds_total: int = 0
    avg_confidence: float = 0.0
    operationalization_rate: float = 0.0
    briefs_published: int = 0
    active_actors: int = 0
    ioc_type_distribution: dict[str, int] = Field(default_factory=dict)
    top_actors: list[dict[str, Any]] = Field(default_factory=list)
    ingestion_timeline: list[dict[str, Any]] = Field(default_factory=list)
    feed_health: list[dict[str, Any]] = Field(default_factory=list)


# ── Feedback ─────────────────────────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    action: str  # true_positive | false_positive | deprecate | revoke
    analyst: str = "unknown"
    reason: str = ""

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed = {"true_positive", "false_positive", "deprecate", "revoke"}
        if v not in allowed:
            raise ValueError(f"action must be one of {allowed}")
        return v


# ── Process ──────────────────────────────────────────────────────────────────

class ProcessIntelRequest(BaseModel):
    intel_records: list[dict[str, Any]] = Field(default_factory=list)
