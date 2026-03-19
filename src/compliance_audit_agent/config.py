"""Configuration for the Compliance and Audit Agent."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All tunables pulled from environment variables."""

    model_config = {"env_prefix": "COMPLIANCE_"}

    # ── Kafka ─────────────────────────────────────────────────────────────
    kafka_bootstrap: str = "localhost:9092"
    kafka_topic: str = "compliance-evidence"
    kafka_group_id: str = "compliance-audit-agent"

    # ── Storage ──────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/1"
    postgres_dsn: str = "postgresql://comp_user:comp_pass@localhost:5432/compliance"

    # ── Evidence Sources ──────────────────────────────────────────────────
    siem_api_url: str = ""
    siem_api_key: str = ""
    edr_api_url: str = ""
    edr_api_key: str = ""
    iam_api_url: str = ""
    iam_api_key: str = ""
    aws_api_url: str = ""
    aws_api_key: str = ""
    azure_api_url: str = ""
    azure_api_key: str = ""
    gcp_api_url: str = ""
    gcp_api_key: str = ""
    cspm_api_url: str = ""
    cspm_api_key: str = ""
    grc_api_url: str = ""
    grc_api_key: str = ""

    # ── ITSM ──────────────────────────────────────────────────────────────
    itsm_api_url: str = ""
    itsm_api_key: str = ""
    itsm_project: str = "COMPLIANCE"

    # ── Frameworks ───────────────────────────────────────────────────────
    enabled_frameworks: str = "ISO27001,NIST_CSF,SOC2,PCI_DSS,HIPAA"
    org_unit: str = "enterprise"

    # ── Scoring ──────────────────────────────────────────────────────────
    effectiveness_threshold_full: float = 85.0
    effectiveness_threshold_partial: float = 60.0
    compliance_drift_alert_threshold: float = 5.0   # % drop in 7 days
    evidence_retention_months: int = 36

    # ── Ports ─────────────────────────────────────────────────────────────
    api_port: int = 8010
    health_port: int = 8090
    metrics_port: int = 9100

    # ── General ──────────────────────────────────────────────────────────
    agent_env: str = "development"
    log_level: str = "INFO"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
