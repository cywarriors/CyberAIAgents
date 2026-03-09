"""Normalised security event models (OCSF-aligned)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    DNS = "dns"
    CLOUD_AUDIT = "cloud_audit"
    IAM = "iam"
    ENDPOINT = "endpoint"
    FIREWALL = "firewall"
    OTHER = "other"


class RawEvent(BaseModel):
    """Incoming raw event before normalisation."""

    source: str = Field(..., description="Originating data source identifier")
    source_type: str = Field(..., description="syslog | cef | json | cloud-native")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class NormalizedEvent(BaseModel):
    """Event normalised to OCSF / ECS common schema."""

    event_id: str
    timestamp: datetime
    category: EventCategory
    source: str
    source_type: str

    # Entity fields
    src_ip: str | None = None
    dst_ip: str | None = None
    user_name: str | None = None
    host_name: str | None = None
    process_name: str | None = None
    domain: str | None = None

    # Action / outcome
    action: str | None = None
    outcome: str | None = None

    # Enrichment
    asset_criticality: str | None = None
    user_department: str | None = None
    user_role: str | None = None

    # Original payload for evidence
    raw_snippet: dict[str, Any] = Field(default_factory=dict)
