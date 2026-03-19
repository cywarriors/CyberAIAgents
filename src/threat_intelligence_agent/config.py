"""Configuration for the Threat Intelligence Agent."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All tunables pulled from environment variables."""

    model_config = {"env_prefix": "THREAT_INTEL_"}

    # ── Kafka ────────────────────────────────────────────────────────────
    kafka_bootstrap: str = "localhost:9092"
    kafka_topic: str = "threat-intel-raw"
    kafka_group_id: str = "threat-intel-agent"

    # ── Redis / PostgreSQL ───────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    postgres_dsn: str = "postgresql://ti_user:ti_pass@localhost:5432/threat_intel"

    # ── Feed Sources ─────────────────────────────────────────────────────
    otx_api_key: str = ""
    otx_base_url: str = "https://otx.alienvault.com/api/v1"
    abusech_base_url: str = "https://urlhaus-api.abuse.ch/v1"
    circl_taxii_url: str = "https://www.circl.lu/taxii"
    commercial_feed_url: str = ""
    commercial_feed_api_key: str = ""
    isac_taxii_url: str = ""
    isac_api_key: str = ""
    internal_ioc_url: str = ""

    # ── Detection Tool Targets ───────────────────────────────────────────
    siem_api_url: str = ""
    siem_api_key: str = ""
    edr_api_url: str = ""
    edr_api_key: str = ""
    firewall_api_url: str = ""
    firewall_api_key: str = ""

    # ── Ticketing ────────────────────────────────────────────────────────
    ticketing_url: str = ""
    ticketing_api_key: str = ""
    ticketing_project: str = "THREAT-INTEL"

    # ── LLM (brief generation assistance) ────────────────────────────────
    llm_endpoint: str = ""
    llm_api_key: str = ""

    # ── Confidence scoring ───────────────────────────────────────────────
    confidence_source_weight: float = 0.35
    confidence_age_weight: float = 0.20
    confidence_corroboration_weight: float = 0.30
    confidence_historical_weight: float = 0.15
    confidence_distribution_threshold: float = 70.0
    ioc_max_age_days: int = 90

    # ── Relevance scoring weights ────────────────────────────────────────
    relevance_industry_weight: float = 0.30
    relevance_geography_weight: float = 0.25
    relevance_attack_surface_weight: float = 0.25
    relevance_historical_weight: float = 0.20

    # ── Organisation context (for relevance) ─────────────────────────────
    org_industry: str = "financial_services"
    org_region: str = "north_america"
    org_asset_types: str = "web_apps,databases,cloud_infra,endpoints"

    # ── Ports ────────────────────────────────────────────────────────────
    api_port: int = 8009
    health_port: int = 8089
    metrics_port: int = 9099

    # ── General ──────────────────────────────────────────────────────────
    agent_env: str = "development"
    log_level: str = "INFO"


@lru_cache()
def get_settings() -> Settings:
    """Return a cached Settings instance (reads env/.env on first call)."""
    from dotenv import load_dotenv

    load_dotenv()
    return Settings()
