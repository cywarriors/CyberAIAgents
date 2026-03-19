"""Domain models for the Compliance and Audit Agent."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Framework(str, Enum):
    ISO27001 = "ISO27001"
    NIST_CSF = "NIST_CSF"
    SOC2 = "SOC2"
    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"
    CUSTOM = "CUSTOM"


class EffectivenessRating(str, Enum):
    FULLY_EFFECTIVE = "fully_effective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    INEFFECTIVE = "ineffective"
    NOT_ASSESSED = "not_assessed"


class EvidenceRecord(BaseModel):
    evidence_id: str
    source_system: str          # SIEM, EDR, IAM, Cloud, etc.
    source_type: str            # log, config, scan_result, policy_doc
    control_id: str             # E.g. ISO27001-A.9.1.1
    framework: Framework
    content: dict[str, Any] = Field(default_factory=dict)
    collected_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    sha256_hash: str = ""       # Filled by GenerateAuditPackNode
    pii_redacted: bool = False


class ControlMapping(BaseModel):
    control_id: str
    framework: Framework
    control_name: str
    evidence_ids: list[str] = Field(default_factory=list)
    cross_framework_ids: list[str] = Field(default_factory=list)  # harmonisation


class ComplianceGap(BaseModel):
    gap_id: str
    control_id: str
    framework: Framework
    description: str
    severity: str               # critical, high, medium, low
    remediation_guidance: str
    ticket_id: Optional[str] = None
    identified_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class AuditPack(BaseModel):
    pack_id: str
    framework: Framework
    org_unit: str
    evidence_ids: list[str] = Field(default_factory=list)
    overall_score: float = 0.0
    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    sha256_manifest: str = ""   # Hash of the entire pack
    version: int = 1
    is_final: bool = False      # HR-IL: awaits Compliance Manager approval


class DriftAlert(BaseModel):
    alert_id: str
    framework: Framework
    previous_score: float
    current_score: float
    delta_pct: float
    period_days: int = 7
    detected_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
