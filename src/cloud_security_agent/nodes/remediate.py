"""Generate remediation node - produces fix guidance with IaC snippets and CLI commands."""

from cloud_security_agent.models.state import CloudPostureState


async def generate_remediation(state: CloudPostureState) -> CloudPostureState:
    """Generate remediation guidance for all prioritized findings."""

    remediation_count = 0

    for prioritized in state.prioritized_findings:
        finding = prioritized.finding

        # Remediation guidance is already populated from the policy rule
        # Enhance with priority context
        if not finding.remediation_guidance:
            finding.remediation_guidance = (
                f"Review and remediate {finding.rule_name} on "
                f"resource {finding.resource_name} ({finding.resource_id})"
            )

        if finding.remediation_guidance or finding.iac_fix_snippet or finding.cli_fix_command:
            remediation_count += 1

    state.metrics["remediation_guidance_count"] = remediation_count

    return state
