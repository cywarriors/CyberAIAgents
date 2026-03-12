"""Centralised configuration loaded from environment variables."""

from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

load_dotenv()


class Settings(BaseSettings):
    """Application settings populated from env vars / .env file."""

    # General
    agent_env: str = Field(default="development")
    log_level: str = Field(default="INFO")

    # Kafka
    kafka_bootstrap_servers: str = Field(default="localhost:9092")
    kafka_consumer_group: str = Field(default="incident-triage-agent")
    kafka_alert_ingest_topic: str = Field(default="security.alerts")
    kafka_triaged_topic: str = Field(default="security.triaged_incidents")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/1")

    # PostgreSQL
    postgres_dsn: str = Field(default="postgresql+asyncpg://agent:agent@localhost:5432/incident_triage")

    # SIEM
    siem_base_url: str = Field(default="https://siem.example.com/api")
    siem_api_key: str = Field(default="")

    # EDR
    edr_base_url: str = Field(default="https://edr.example.com/api")
    edr_api_key: str = Field(default="")

    # Ticketing / ITSM
    ticketing_base_url: str = Field(default="https://tickets.example.com/api")
    ticketing_api_key: str = Field(default="")

    # Messaging
    messaging_webhook_url: str = Field(default="")

    # Threat Intel
    threat_intel_base_url: str = Field(default="https://tip.example.com/api")
    threat_intel_api_key: str = Field(default="")

    # CMDB / Asset Inventory
    cmdb_base_url: str = Field(default="https://cmdb.example.com/api")
    cmdb_api_key: str = Field(default="")

    # Identity Directory (LDAP / Graph API)
    identity_base_url: str = Field(default="https://identity.example.com/api")
    identity_api_key: str = Field(default="")

    # Vulnerability Context
    vuln_base_url: str = Field(default="https://vuln.example.com/api")
    vuln_api_key: str = Field(default="")

    # LLM Service (for triage summary generation)
    llm_base_url: str = Field(default="http://localhost:8501/v1")
    llm_api_key: str = Field(default="")

    # Monitoring
    prometheus_port: int = Field(default=9091)
    health_check_port: int = Field(default=8081)

    # Triage tuning
    correlation_window_seconds: int = Field(default=600)
    dedup_window_seconds: int = Field(default=300)
    severity_threshold_for_paging: str = Field(default="Critical")
    confidence_threshold: int = Field(default=50)

    # Priority scoring weights (configurable per FR-04/FR-11)
    weight_asset_criticality: float = Field(default=0.25)
    weight_threat_intel: float = Field(default=0.20)
    weight_user_risk: float = Field(default=0.15)
    weight_alert_severity: float = Field(default=0.25)
    weight_historical_accuracy: float = Field(default=0.15)

    model_config = {"env_prefix": "", "case_sensitive": False}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
