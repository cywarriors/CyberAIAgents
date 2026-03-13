"""Centralised configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # General
    agent_env: str = Field(default="development")
    log_level: str = Field(default="INFO")

    # API
    api_host: str = Field(default="127.0.0.1")
    api_port: int = Field(default=8005)
    api_debug: bool = Field(default=False)

    # Kafka
    kafka_bootstrap_servers: str = Field(default="localhost:9092")
    kafka_consumer_group: str = Field(default="phishing-defense-agent")
    kafka_email_ingest_topic: str = Field(default="email.inbound")
    kafka_verdict_topic: str = Field(default="email.verdicts")
    kafka_ioc_topic: str = Field(default="threat.iocs")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/5")

    # PostgreSQL
    postgres_dsn: str = Field(
        default="postgresql+asyncpg://agent:agent@localhost:5432/phishing_defense"
    )

    # Email gateway
    email_gateway_base_url: str = Field(default="https://gateway.example.com/api")
    email_gateway_api_key: str = Field(default="")

    # M365 / Google Workspace tenant
    tenant_api_base_url: str = Field(default="https://graph.microsoft.com/v1.0")
    tenant_api_token: str = Field(default="")

    # Sandbox (URL / attachment detonation)
    sandbox_base_url: str = Field(default="https://sandbox.example.com/api")
    sandbox_api_key: str = Field(default="")
    sandbox_timeout_seconds: int = Field(default=30)

    # Threat intelligence
    threat_intel_base_url: str = Field(default="http://localhost:9001")
    threat_intel_api_key: str = Field(default="")

    # SIEM
    siem_base_url: str = Field(default="https://siem.example.com/api")
    siem_api_key: str = Field(default="")

    # Ticketing
    ticketing_base_url: str = Field(default="https://tickets.example.com/api")
    ticketing_api_key: str = Field(default="")

    # Messaging (Slack/Teams webhook)
    messaging_webhook_url: str = Field(default="")

    # Monitoring
    prometheus_port: int = Field(default=9095)
    health_check_port: int = Field(default=8085)

    # Verdict thresholds
    risk_threshold_block: float = Field(default=80.0)
    risk_threshold_quarantine: float = Field(default=60.0)
    risk_threshold_warn: float = Field(default=40.0)

    # Scoring weights (sum to 1.0)
    weight_sender_auth: float = Field(default=0.20)
    weight_content_analysis: float = Field(default=0.25)
    weight_url_reputation: float = Field(default=0.20)
    weight_attachment_risk: float = Field(default=0.20)
    weight_threat_intel: float = Field(default=0.15)

    # VIP protection
    vip_domains: str = Field(default="")
    vip_users: str = Field(default="")

    # Allowed origins / hosts (security)
    allowed_origins: str = Field(
        default="http://localhost:3000,http://localhost:3005,http://localhost:5176"
    )
    allowed_hosts: str = Field(default="localhost,127.0.0.1")

    model_config = {"env_prefix": "PHISHING_", "case_sensitive": False}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
