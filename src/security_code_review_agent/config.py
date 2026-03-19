from __future__ import annotations
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # VCS
    vcs_api_url: str = ""
    vcs_api_token: str = ""
    vcs_platform: str = "github"  # github/gitlab/azuredevops

    # Vulnerability databases
    nvd_api_url: str = ""
    nvd_api_key: str = ""
    osv_api_url: str = ""

    # ITSM
    itsm_api_url: str = ""
    itsm_api_key: str = ""
    itsm_project: str = "SEC"

    # SIEM
    siem_api_url: str = ""
    siem_api_key: str = ""

    # Policy gates
    policy_block_severity: str = "critical"  # critical/high/medium/low
    policy_warn_severity: str = "high"

    # Supported languages
    supported_languages: str = "python,javascript,java,go,csharp"

    # Ports
    api_port: int = 8011
    health_port: int = 8091
    metrics_port: int = 9101

    agent_env: str = "production"
    log_level: str = "INFO"

    class Config:
        env_prefix = "CODE_REVIEW_"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()
