"""Centralised configuration loaded from environment variables."""

from __future__ import annotations

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

    # Message queue
    kafka_bootstrap_servers: str = Field(default="localhost:9092")
    kafka_consumer_group: str = Field(default="vapt-agent")
    kafka_scan_request_topic: str = Field(default="vapt.scan_requests")
    kafka_findings_topic: str = Field(default="vapt.findings")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/1")

    # PostgreSQL
    postgres_dsn: str = Field(default="postgresql+asyncpg://agent:agent@localhost:5432/vapt")

    # Scanner engines
    nmap_path: str = Field(default="/usr/bin/nmap")
    nuclei_api_url: str = Field(default="http://localhost:8081/api")
    nuclei_api_key: str = Field(default="")
    zap_api_url: str = Field(default="http://localhost:8082/api")
    zap_api_key: str = Field(default="")
    nessus_api_url: str = Field(default="https://nessus.example.com/api")
    nessus_api_key: str = Field(default="")

    # NVD / EPSS / KEV enrichment
    nvd_api_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str = Field(default="")
    epss_api_url: str = Field(default="https://api.first.org/data/v1/epss")
    kev_api_url: str = Field(default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")

    # CMDB / Asset Inventory
    cmdb_base_url: str = Field(default="https://cmdb.example.com/api")
    cmdb_api_key: str = Field(default="")

    # Ticketing
    ticketing_base_url: str = Field(default="https://tickets.example.com/api")
    ticketing_api_key: str = Field(default="")

    # Messaging / Notifications
    messaging_webhook_url: str = Field(default="")

    # Reporting
    report_output_dir: str = Field(default="/tmp/vapt-reports")

    # Credential vault
    credential_vault_url: str = Field(default="https://vault.example.com/v1")
    credential_vault_token: str = Field(default="")

    # Cloud provider APIs
    aws_access_key_id: str = Field(default="")
    aws_secret_access_key: str = Field(default="")
    azure_tenant_id: str = Field(default="")
    azure_client_id: str = Field(default="")
    azure_client_secret: str = Field(default="")
    gcp_service_account_json: str = Field(default="")

    # Monitoring
    prometheus_port: int = Field(default=9091)
    health_check_port: int = Field(default=8083)

    # VAPT tuning
    dedup_window_seconds: int = Field(default=600)
    max_concurrent_scans: int = Field(default=50)
    exploitation_timeout_seconds: int = Field(default=60)
    scan_timeout_minutes: int = Field(default=120)

    # Scoring weights (sum to 1.0)
    weight_cvss: float = Field(default=0.30)
    weight_epss: float = Field(default=0.20)
    weight_exploitability: float = Field(default=0.25)
    weight_asset_criticality: float = Field(default=0.15)
    weight_exposure: float = Field(default=0.10)

    model_config = {"env_prefix": "", "case_sensitive": False}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
