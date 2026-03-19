"""Domain models for the Threat Intelligence Agent."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    URL = "url"
    EMAIL = "email"


class TLPLevel(str, Enum):
    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


class IntelLifecycle(str, Enum):
    NEW = "new"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class SourceType(str, Enum):
    OSINT = "osint"
    COMMERCIAL = "commercial"
    ISAC = "isac"
    INTERNAL = "internal"


class BriefLevel(str, Enum):
    STRATEGIC = "strategic"
    OPERATIONAL = "operational"
    TACTICAL = "tactical"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


# ── Pydantic Models ─────────────────────────────────────────────────────────

class RawIntelRecord(BaseModel):
    record_id: str
    source_name: str
    source_type: SourceType
    tlp: TLPLevel = TLPLevel.GREEN
    timestamp: str
    raw_payload: dict = Field(default_factory=dict)


class STIXObject(BaseModel):
    stix_id: str
    stix_type: str = "indicator"
    indicator_type: IOCType
    value: str
    labels: list[str] = Field(default_factory=list)
    kill_chain_phases: list[str] = Field(default_factory=list)
    created: str = ""
    modified: str = ""
    source_refs: list[str] = Field(default_factory=list)
    tlp: TLPLevel = TLPLevel.GREEN


class IOCRecord(BaseModel):
    ioc_id: str
    ioc_type: IOCType
    value: str
    sources: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    provenance: list[dict] = Field(default_factory=list)
    lifecycle: IntelLifecycle = IntelLifecycle.NEW
    tlp: TLPLevel = TLPLevel.GREEN


class ConfidenceScore(BaseModel):
    ioc_id: str
    value: str
    ioc_type: IOCType
    confidence: float = 0.0
    source_reliability: float = 0.0
    age_factor: float = 1.0
    corroboration_count: int = 0
    explanation: str = ""


class RelevanceScore(BaseModel):
    ioc_id: str
    value: str
    relevance: float = 0.0
    industry_score: float = 0.0
    geography_score: float = 0.0
    attack_surface_score: float = 0.0
    historical_score: float = 0.0
    explanation: str = ""


class ATTCKMapping(BaseModel):
    entity_id: str
    entity_type: str = "ioc"
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    actor: str = ""
    campaign: str = ""
    confidence: float = 0.0


class IntelBrief(BaseModel):
    brief_id: str
    level: BriefLevel
    title: str
    executive_summary: str = ""
    technical_analysis: str = ""
    ioc_appendix: list[dict] = Field(default_factory=list)
    attck_mapping: list[dict] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    created: str = ""
    tlp: TLPLevel = TLPLevel.GREEN


class FeedSource(BaseModel):
    feed_id: str
    name: str
    source_type: SourceType
    url: str = ""
    enabled: bool = True
    last_poll: str = ""
    success_rate: float = 1.0
    ioc_yield: int = 0
    quality_score: float = 50.0
    false_positive_rate: float = 0.0


class FeedHealth(BaseModel):
    feed_id: str
    name: str
    status: str = "healthy"
    last_poll: str = ""
    success_rate: float = 1.0
    ioc_yield: int = 0
    error_message: Optional[str] = None


class ThreatActorProfile(BaseModel):
    actor_id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    targeted_sectors: list[str] = Field(default_factory=list)
    targeted_regions: list[str] = Field(default_factory=list)
    ttps: list[dict] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    associated_iocs: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    confidence: float = 0.0


class Campaign(BaseModel):
    campaign_id: str
    name: str
    description: str = ""
    actor: str = ""
    start_date: str = ""
    end_date: Optional[str] = None
    targeted_sectors: list[str] = Field(default_factory=list)
    targeted_regions: list[str] = Field(default_factory=list)
    ttps: list[dict] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    status: str = "active"
