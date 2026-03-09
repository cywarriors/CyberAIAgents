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
    kafka_consumer_group: str = Field(default="threat-detection-agent")
    kafka_telemetry_topic: str = Field(default="security.telemetry")
    kafka_alert_topic: str = Field(default="security.alerts")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0")

    # PostgreSQL
    postgres_dsn: str = Field(default="postgresql+asyncpg://agent:agent@localhost:5432/threat_detection")

    # SIEM
    siem_base_url: str = Field(default="https://siem.example.com/api")
    siem_api_key: str = Field(default="")

    # EDR
    edr_base_url: str = Field(default="https://edr.example.com/api")
    edr_api_key: str = Field(default="")

    # Ticketing
    ticketing_base_url: str = Field(default="https://tickets.example.com/api")
    ticketing_api_key: str = Field(default="")

    # Messaging
    messaging_webhook_url: str = Field(default="")

    # Threat Intel
    threat_intel_base_url: str = Field(default="https://tip.example.com/api")
    threat_intel_api_key: str = Field(default="")

    # CMDB
    cmdb_base_url: str = Field(default="https://cmdb.example.com/api")
    cmdb_api_key: str = Field(default="")

    # Model Inference
    model_inference_url: str = Field(default="http://localhost:8501/v1/models/anomaly:predict")

    # Monitoring
    prometheus_port: int = Field(default=9090)
    health_check_port: int = Field(default=8080)

    # Detection tuning
    dedup_window_seconds: int = Field(default=300)
    severity_threshold_for_paging: str = Field(default="Critical")
    confidence_threshold: int = Field(default=50)

    model_config = {"env_prefix": "", "case_sensitive": False}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
