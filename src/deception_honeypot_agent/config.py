from __future__ import annotations
from functools import lru_cache
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings  # type: ignore


class Settings(BaseSettings):
    # SIEM integration
    siem_api_url: str = ""
    siem_api_key: str = ""

    # Threat intelligence
    threat_intel_api_url: str = ""
    threat_intel_api_key: str = ""

    # Infrastructure API for decoy provisioning
    infra_api_url: str = ""
    infra_api_key: str = ""

    # ITSM
    itsm_api_url: str = ""
    itsm_api_key: str = ""

    # Deception strategy
    max_decoys: int = 50
    rotation_interval_hours: int = 24
    coverage_target_percent: float = 80.0

    # Ports
    api_port: int = 8012
    health_port: int = 8092
    metrics_port: int = 9102

    agent_env: str = "production"
    log_level: str = "INFO"

    class Config:
        env_prefix = "DECEPTION_"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()
