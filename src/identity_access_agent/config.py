"""Centralised, environment-driven configuration for the Identity & Access Monitoring Agent (SRS-06)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All tunables exposed as environment variables with ``IDENTITY_`` prefix."""

    # ── General ────────────────────────────────────────────────────
    agent_env: str = "development"
    log_level: str = "INFO"

    # ── API / BFF ──────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8006
    api_debug: bool = False

    # ── Kafka ──────────────────────────────────────────────────────
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_auth_events: str = "identity.auth_events"
    kafka_topic_role_changes: str = "identity.role_changes"
    kafka_topic_risk_alerts: str = "identity.risk_alerts"
    kafka_group_id: str = "identity-access-agent"

    # ── Redis ──────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/6"

    # ── PostgreSQL ─────────────────────────────────────────────────
    postgres_dsn: str = "postgresql+asyncpg://agent:agent@localhost:5432/identity_access"

    # ── Integration endpoints ──────────────────────────────────────
    idp_api_url: str = "https://idp.internal/api/v1"
    mfa_api_url: str = "https://mfa.internal/api/v1"
    edr_api_url: str = "https://edr.internal/api/v1"
    casb_api_url: str = "https://casb.internal/api/v1"
    siem_api_url: str = "https://siem.internal/api/v1"
    ticketing_api_url: str = "https://tickets.internal/api/v1"
    geoip_api_url: str = "https://geoip.internal/api/v1"
    messaging_webhook_url: str = "https://chat.internal/webhook"

    # ── Monitoring ─────────────────────────────────────────────────
    prometheus_port: int = 9096
    health_check_port: int = 8086

    # ── Risk thresholds ────────────────────────────────────────────
    risk_threshold_critical: float = 85.0
    risk_threshold_high: float = 65.0
    risk_threshold_medium: float = 40.0

    # ── Scoring weights (must sum to 1.0) ──────────────────────────
    weight_session_anomaly: float = 0.25
    weight_auth_failure: float = 0.20
    weight_privilege_change: float = 0.20
    weight_takeover_signals: float = 0.20
    weight_context_enrichment: float = 0.15

    # ── Impossible-travel ──────────────────────────────────────────
    impossible_travel_speed_kmh: float = 900.0  # max plausible speed
    impossible_travel_min_distance_km: float = 500.0

    # ── MFA fatigue ────────────────────────────────────────────────
    mfa_fatigue_window_minutes: int = 10
    mfa_fatigue_threshold: int = 5

    # ── VPN / allow-lists ──────────────────────────────────────────
    vpn_allowed_ips: str = ""  # comma-separated

    # ── Security ───────────────────────────────────────────────────
    allowed_origins: str = "http://localhost:5177,http://127.0.0.1:5177"
    allowed_hosts: str = "localhost,127.0.0.1"

    model_config = {"env_prefix": "IDENTITY_", "case_sensitive": False}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
