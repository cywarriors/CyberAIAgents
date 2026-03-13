"""Configuration for Cloud Security Posture Management Agent."""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import ConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8")

    # API Configuration
    cspm_api_host: str = "127.0.0.1"
    cspm_api_port: int = 8006
    cspm_api_debug: bool = False

    # Security
    allowed_origins: str = "http://localhost:3000,http://localhost:3006,http://localhost:8006"
    allowed_hosts: str = "localhost,127.0.0.1"

    # Cloud Provider Configuration
    aws_enabled: bool = True
    azure_enabled: bool = True
    gcp_enabled: bool = True

    # AWS Configuration
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_role_arn: Optional[str] = None

    # Azure Configuration
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_subscription_id: Optional[str] = None

    # GCP Configuration
    gcp_project_id: Optional[str] = None
    gcp_credentials_path: Optional[str] = None

    # Risk Scoring Weights (sum to 1.0)
    risk_weight_severity: float = 0.30
    risk_weight_exposure: float = 0.25
    risk_weight_blast_radius: float = 0.20
    risk_weight_asset_criticality: float = 0.15
    risk_weight_compliance_impact: float = 0.10

    # Compliance Frameworks
    enable_cis_benchmarks: bool = True
    enable_nist_800_53: bool = True
    enable_custom_policies: bool = True

    # IaC Scanning
    iac_scan_timeout_seconds: int = 60
    iac_supported_formats: str = "terraform,cloudformation,bicep"

    # Scan Scheduling
    full_scan_interval_minutes: int = 30
    drift_check_interval_minutes: int = 15
    max_concurrent_account_scans: int = 10

    # Severity Thresholds
    risk_threshold_critical: float = 80.0
    risk_threshold_high: float = 60.0
    risk_threshold_medium: float = 40.0

    # Integration Endpoints
    siem_api_url: Optional[str] = None
    itsm_api_url: Optional[str] = None
    itsm_system: str = "mock"  # mock, jira, servicenow
    itsm_api_key: Optional[str] = None
    git_api_url: Optional[str] = None
    git_api_token: Optional[str] = None
    opa_api_url: Optional[str] = None

    # Database Configuration
    database_url: str = "sqlite:///./cloud_security.db"
    findings_retention_days: int = 730  # 24 months
    snapshot_retention_days: int = 365  # 12 months
    compliance_report_retention_days: int = 1095  # 36 months

    # Monitoring and Observability
    enable_metrics: bool = True
    metrics_port: int = 8007
    log_level: str = "info"

    # Authentication
    oidc_provider_url: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None
    session_timeout_minutes: int = 30


# Global settings instance
settings = Settings()
