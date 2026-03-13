"""Evaluate policies node - checks configurations against CIS/NIST/custom rules."""

from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.models import ComplianceStatus
from cloud_security_agent.rules import PolicyEngine, DEFAULT_POLICY_RULES


async def evaluate_policies(state: CloudPostureState) -> dict:
    """Evaluate all discovered resources against applicable policy rules."""

    policy_rules = state.policy_rules if state.policy_rules else DEFAULT_POLICY_RULES
    findings = []

    for resource in state.resource_inventory:
        for rule in policy_rules:
            # Check if rule applies to this resource type and provider
            if (
                resource.resource_type in rule.resource_types
                and resource.provider in rule.providers
            ):
                finding = PolicyEngine.evaluate_resource(resource, rule)
                if finding.status == ComplianceStatus.FAIL:
                    findings.append(finding)

    # Count findings by severity
    severity_counts: dict[str, int] = {}
    for finding in findings:
        sev = finding.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "policy_results": findings,
        "metrics": {
            "policy_findings_count": len(findings),
            "rules_evaluated": len(policy_rules),
            "findings_by_severity": severity_counts,
        },
    }
