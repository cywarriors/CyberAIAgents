from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    GO = "go"
    CSHARP = "csharp"
    TYPESCRIPT = "typescript"
    RUBY = "ruby"
    PHP = "php"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PolicyVerdict(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    PASS = "pass"


class FindingStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"


class SASTFinding(BaseModel):
    finding_id: str
    file_path: str
    line_number: int
    column: int
    severity: Severity
    cwe_id: str
    owasp_category: str
    description: str
    code_snippet: str  # Redacted per SEC-03 — max 100 chars, no sensitive values
    language: Language
    rule_id: str
    status: FindingStatus = FindingStatus.NEW


class SecretFinding(BaseModel):
    finding_id: str
    file_path: str
    line_number: int
    secret_type: str
    redacted_value: str  # SEC-02: MUST always be "[REDACTED]" — never store actual secret
    severity: Severity = Severity.CRITICAL
    status: FindingStatus = FindingStatus.NEW


class SCAFinding(BaseModel):
    finding_id: str
    package_name: str
    package_version: str
    cve_id: str
    severity: Severity
    cvss_score: float
    fix_version: str
    language: Language


class FixSuggestion(BaseModel):
    suggestion_id: str
    finding_id: str
    finding_type: str  # sast / secret / sca
    description: str
    code_example: str
    confidence_score: float


class SBOMComponent(BaseModel):
    name: str
    version: str
    purl: str
    licenses: list[str] = []
    vulnerabilities: list[str] = []


class SBOM(BaseModel):
    sbom_id: str
    format: str = "cyclonedx"
    spec_version: str = "1.4"
    repository: str
    components: list[SBOMComponent] = []
    generated_at: str


class PRComment(BaseModel):
    comment_id: str
    file_path: str
    line_number: int
    body: str
    severity: str
    posted: bool = False
