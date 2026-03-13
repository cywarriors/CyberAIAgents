"""Prioritize findings node - risk-ranks findings by blast radius and exposure."""

from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.models import (
    PrioritizedFinding,
    SeverityLevel,
    ExposureLevel,
    ComplianceStatus,
)
from cloud_security_agent.config import settings


def get_severity_score(severity: SeverityLevel) -> float:
    """Map severity to a 0-100 score."""
    scores = {
        SeverityLevel.CRITICAL: 100,
        SeverityLevel.HIGH: 75,
        SeverityLevel.MEDIUM: 50,
        SeverityLevel.LOW: 25,
        SeverityLevel.INFO: 10,
    }
    return scores.get(severity, 50)


def get_exposure_score(exposure: ExposureLevel) -> float:
    """Map exposure to a 0-100 score."""
    scores = {
        ExposureLevel.PUBLIC: 100,
        ExposureLevel.INTERNET_FACING: 80,
        ExposureLevel.INTERNAL: 40,
        ExposureLevel.PRIVATE: 20,
    }
    return scores.get(exposure, 40)


def get_blast_radius_score(blast_radius: str) -> float:
    """Map blast radius to a 0-100 score."""
    scores = {
        "account-wide": 100,
        "region-wide": 70,
        "service-wide": 50,
        "resource-level": 30,
    }
    return scores.get(blast_radius, 30)


def get_criticality_score(criticality: str) -> float:
    """Map asset criticality to a 0-100 score."""
    scores = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
    }
    return scores.get(criticality.lower(), 50)


def determine_blast_radius(resource_type: str, finding_rule_id: str) -> str:
    """Determine blast radius based on resource type and finding."""
    # IAM findings affect entire account
    if "iam" in resource_type.lower() or "iam" in finding_rule_id.lower():
        return "account-wide"
    # Networking findings affect region
    if any(t in resource_type.lower() for t in ["vpc", "security_group", "network"]):
        return "region-wide"
    # Service-level findings
    if any(t in resource_type.lower() for t in ["cloudtrail", "config", "logging"]):
        return "service-wide"
    return "resource-level"


async def prioritize_findings(state: CloudPostureState) -> CloudPostureState:
    """Compute composite risk scores and prioritize findings."""

    # Build resource lookup for enrichment
    resource_lookup: dict[str, dict] = {}
    for resource in state.resource_inventory:
        resource_lookup[resource.resource_id] = {
            "exposure": resource.exposure,
            "criticality": resource.criticality,
        }

    prioritized: list[PrioritizedFinding] = []

    # Merge policy_results and IaC findings
    all_findings = list(state.policy_results)
    for iac_result in state.iac_scan_results:
        all_findings.extend(iac_result.findings)

    for finding in all_findings:
        if finding.status != ComplianceStatus.FAIL:
            continue

        resource_info = resource_lookup.get(finding.resource_id, {})
        exposure = resource_info.get("exposure", ExposureLevel.INTERNAL)
        criticality = resource_info.get("criticality", "medium")
        blast_radius = determine_blast_radius(finding.resource_type, finding.rule_id)

        # Count frameworks affected
        frameworks_affected = [finding.framework]

        # Calculate component scores
        sev_score = get_severity_score(finding.severity)
        exp_score = get_exposure_score(exposure)
        blast_score = get_blast_radius_score(blast_radius)
        crit_score = get_criticality_score(criticality)
        compliance_impact = len(frameworks_affected) * 50  # More frameworks = higher impact

        # Weighted composite
        composite = (
            sev_score * settings.risk_weight_severity
            + exp_score * settings.risk_weight_exposure
            + blast_score * settings.risk_weight_blast_radius
            + crit_score * settings.risk_weight_asset_criticality
            + min(compliance_impact, 100) * settings.risk_weight_compliance_impact
        )
        composite = min(100.0, composite)

        # Determine tier
        if composite >= settings.risk_threshold_critical:
            tier = SeverityLevel.CRITICAL
        elif composite >= settings.risk_threshold_high:
            tier = SeverityLevel.HIGH
        elif composite >= settings.risk_threshold_medium:
            tier = SeverityLevel.MEDIUM
        else:
            tier = SeverityLevel.LOW

        explanation = (
            f"Severity: {sev_score:.0f} ({settings.risk_weight_severity*100:.0f}%) + "
            f"Exposure: {exp_score:.0f} ({settings.risk_weight_exposure*100:.0f}%) + "
            f"Blast Radius: {blast_score:.0f} ({settings.risk_weight_blast_radius*100:.0f}%) + "
            f"Criticality: {crit_score:.0f} ({settings.risk_weight_asset_criticality*100:.0f}%) + "
            f"Compliance: {min(compliance_impact, 100):.0f} ({settings.risk_weight_compliance_impact*100:.0f}%) "
            f"= {composite:.1f}"
        )

        prioritized.append(PrioritizedFinding(
            finding=finding,
            composite_risk_score=composite,
            risk_tier=tier,
            blast_radius=blast_radius,
            exposure_level=exposure,
            asset_criticality=criticality,
            compliance_frameworks_affected=frameworks_affected,
            risk_explanation=explanation,
            severity_score=sev_score * settings.risk_weight_severity,
            exposure_score=exp_score * settings.risk_weight_exposure,
            blast_radius_score=blast_score * settings.risk_weight_blast_radius,
            criticality_score=crit_score * settings.risk_weight_asset_criticality,
            compliance_score=min(compliance_impact, 100) * settings.risk_weight_compliance_impact,
        ))

    # Sort by risk score descending
    prioritized.sort(key=lambda f: f.composite_risk_score, reverse=True)

    state.prioritized_findings = prioritized
    state.metrics["prioritized_count"] = len(prioritized)
    state.metrics["critical_findings"] = len([f for f in prioritized if f.risk_tier == SeverityLevel.CRITICAL])
    state.metrics["high_findings"] = len([f for f in prioritized if f.risk_tier == SeverityLevel.HIGH])
    state.metrics["medium_findings"] = len([f for f in prioritized if f.risk_tier == SeverityLevel.MEDIUM])
    state.metrics["low_findings"] = len([f for f in prioritized if f.risk_tier == SeverityLevel.LOW])

    return state
