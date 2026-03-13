"""Publish and ticket node - sends alerts, creates tickets, updates dashboards."""

from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.models import (
    SeverityLevel,
    ComplianceScore,
    ComplianceStatus,
)
from cloud_security_agent.integrations.ticketing import MockTicketingClient
from cloud_security_agent.integrations.siem import MockSIEMClient


async def publish_and_ticket(state: CloudPostureState) -> CloudPostureState:
    """Send alerts for critical findings and create remediation tickets."""

    ticketing = MockTicketingClient()
    siem = MockSIEMClient()

    tickets_created: dict[str, str] = {}
    alerts_sent: list[str] = []

    for prioritized in state.prioritized_findings:
        finding = prioritized.finding

        # Send SIEM alert for critical and high findings
        if prioritized.risk_tier in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
            alert_id = await siem.send_alert(
                finding_id=finding.finding_id,
                severity=finding.severity.value,
                title=finding.rule_name,
                description=finding.description,
                resource_id=finding.resource_id,
                account_id=finding.account_id,
                provider=finding.provider.value,
            )
            alerts_sent.append(alert_id)

        # Create ticket for all failed findings
        ticket_id = await ticketing.create_remediation_ticket(
            finding_id=finding.finding_id,
            severity=finding.severity.value,
            title=finding.rule_name,
            description=finding.description,
            resource_id=finding.resource_id,
            account_id=finding.account_id,
            owner_email="cloud-security@example.com",
        )
        tickets_created[finding.finding_id] = ticket_id
        finding.ticket_id = ticket_id

    # Calculate compliance scores per account and framework
    compliance_scores: dict[str, ComplianceScore] = {}
    account_framework_map: dict[str, dict[str, dict]] = {}

    for resource in state.resource_inventory:
        key = f"{resource.account_id}"
        if key not in account_framework_map:
            account_framework_map[key] = {}

    # Count pass/fail per account per framework from policy results
    for finding in state.policy_results:
        acct = finding.account_id
        fw = finding.framework
        afw_key = f"{acct}:{fw}"
        if afw_key not in account_framework_map.get(acct, {}):
            if acct not in account_framework_map:
                account_framework_map[acct] = {}
            account_framework_map[acct][fw] = {"pass": 0, "fail": 0, "na": 0}

        if finding.status == ComplianceStatus.FAIL:
            account_framework_map[acct][fw]["fail"] += 1
        elif finding.status == ComplianceStatus.PASS:
            account_framework_map[acct][fw]["pass"] += 1
        else:
            account_framework_map[acct][fw]["na"] += 1

    for acct, frameworks in account_framework_map.items():
        for fw, counts in frameworks.items():
            total = counts["pass"] + counts["fail"]
            score_pct = (counts["pass"] / max(total, 1)) * 100
            score_key = f"{acct}:{fw}"
            compliance_scores[score_key] = ComplianceScore(
                account_id=acct,
                framework=fw,
                total_controls=total + counts["na"],
                passed_controls=counts["pass"],
                failed_controls=counts["fail"],
                not_applicable_controls=counts["na"],
                score_percent=score_pct,
            )

    state.tickets_created = tickets_created
    state.alerts_sent = alerts_sent
    state.compliance_scores = compliance_scores
    state.metrics["tickets_created"] = len(tickets_created)
    state.metrics["alerts_sent"] = len(alerts_sent)
    state.metrics["compliance_scores_computed"] = len(compliance_scores)

    return state
