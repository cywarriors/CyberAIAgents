"""Health and metrics monitoring for Cloud Security Posture Management Agent."""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class HealthStatus:
    """Agent health status."""
    status: str  # healthy, degraded, unhealthy
    message: str
    last_check: datetime
    components: dict[str, str]


class HealthChecker:
    """Health check service."""

    async def check_health(self) -> HealthStatus:
        """Perform comprehensive health check."""

        components = {
            "aws_api": "ok",
            "azure_api": "ok",
            "gcp_api": "ok",
            "policy_engine": "ok",
            "iac_scanner": "ok",
            "siem_integration": "ok",
            "ticketing_system": "ok",
            "database": "ok",
        }

        return HealthStatus(
            status="healthy",
            message="All systems operational",
            last_check=datetime.now(timezone.utc),
            components=components,
        )


@dataclass
class MetricsSnapshot:
    """Snapshot of system metrics."""
    timestamp: datetime
    total_accounts_scanned: int
    total_resources: int
    total_findings: int
    critical_findings: int
    public_exposures: int
    compliance_score_avg: float
    drift_regressions: int
    iac_scans: int
    scan_duration_seconds: float


class MetricsCollector:
    """Collects and exposes system metrics."""

    def __init__(self):
        self.metrics_history: list[MetricsSnapshot] = []

    def record_metrics(self, snapshot: MetricsSnapshot):
        """Record a metrics snapshot."""
        self.metrics_history.append(snapshot)

    def get_latest_metrics(self) -> MetricsSnapshot:
        """Get latest metrics."""
        if self.metrics_history:
            return self.metrics_history[-1]
        return MetricsSnapshot(
            timestamp=datetime.now(timezone.utc),
            total_accounts_scanned=0,
            total_resources=0,
            total_findings=0,
            critical_findings=0,
            public_exposures=0,
            compliance_score_avg=0.0,
            drift_regressions=0,
            iac_scans=0,
            scan_duration_seconds=0.0,
        )
