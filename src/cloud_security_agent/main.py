"""Main entry point for Cloud Security Posture Management Agent."""

import asyncio
import logging
from structlog import get_logger
from cloud_security_agent.config import settings
from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.models import DashboardMetrics
from cloud_security_agent.graph import cspm_graph

# Configure logging
logging.basicConfig(level=settings.log_level.upper())
logger = get_logger(__name__)


async def run_cspm_pipeline(initial_state: CloudPostureState) -> CloudPostureState:
    """Execute the cloud security posture management pipeline."""

    logger.info("Starting CSPM pipeline")
    logger.info(
        "Processing",
        accounts=len(initial_state.cloud_accounts),
        resources=len(initial_state.resource_inventory),
    )

    try:
        result = await cspm_graph.ainvoke(initial_state)
        logger.info("Pipeline completed successfully")
        return result
    except Exception as e:
        logger.error("Pipeline failed", error=str(e), exc_info=True)
        initial_state.processing_errors.append(str(e))
        return initial_state


def generate_dashboard_metrics(final_state: CloudPostureState) -> DashboardMetrics:
    """Generate dashboard metrics from final pipeline state."""

    findings_by_severity = {
        "critical": final_state.metrics.get("critical_findings", 0),
        "high": final_state.metrics.get("high_findings", 0),
        "medium": final_state.metrics.get("medium_findings", 0),
        "low": final_state.metrics.get("low_findings", 0),
    }

    findings_by_provider: dict[str, int] = {}
    for f in final_state.prioritized_findings:
        provider = f.finding.provider.value
        findings_by_provider[provider] = findings_by_provider.get(provider, 0) + 1

    # Calculate overall compliance score
    scores = final_state.compliance_scores.values()
    overall_score = (
        sum(s.score_percent for s in scores) / max(len(list(scores)), 1)
        if scores
        else 0.0
    )

    compliance_by_framework: dict[str, float] = {}
    for score in final_state.compliance_scores.values():
        fw = score.framework
        if fw not in compliance_by_framework:
            compliance_by_framework[fw] = score.score_percent
        else:
            compliance_by_framework[fw] = (
                compliance_by_framework[fw] + score.score_percent
            ) / 2

    public_exposure_count = len(
        [
            r
            for r in final_state.resource_inventory
            if r.exposure.value in ("public", "internet_facing")
        ]
    )

    return DashboardMetrics(
        total_accounts=len(final_state.cloud_accounts),
        total_resources=len(final_state.resource_inventory),
        total_findings=len(final_state.prioritized_findings),
        findings_by_severity=findings_by_severity,
        findings_by_provider=findings_by_provider,
        overall_compliance_score=overall_score,
        compliance_by_framework=compliance_by_framework,
        public_exposure_count=public_exposure_count,
        drift_count_24h=final_state.metrics.get("drift_total", 0),
        iac_scans_count=final_state.metrics.get("iac_scans_count", 0),
        iac_block_rate=final_state.metrics.get("iac_block_rate", 0.0),
    )


async def main():
    """Main entry point."""

    logger.info("Cloud Security Posture Management Agent started")

    initial_state = CloudPostureState()
    final_state = await run_cspm_pipeline(initial_state)

    dashboard_metrics = generate_dashboard_metrics(final_state)
    logger.info("Dashboard metrics generated", total_findings=dashboard_metrics.total_findings)

    return final_state


if __name__ == "__main__":
    asyncio.run(main())
