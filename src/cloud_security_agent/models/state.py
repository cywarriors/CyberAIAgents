"""State model for the Cloud Security Posture Management Agent graph."""

import operator
from typing import Annotated, Any
from dataclasses import dataclass, field
from cloud_security_agent.models import (
    CloudAccount,
    CloudResource,
    PolicyFinding,
    PolicyRule,
    IaCScanResult,
    PrioritizedFinding,
    DriftRecord,
    ComplianceScore,
)


def _merge_dicts(a: dict, b: dict) -> dict:
    """Merge two dicts, with b's values overriding a's."""
    merged = {**a, **b}
    return merged


def _last_value(a: Any, b: Any) -> Any:
    """Keep the last (most recent) value."""
    return b if b else a


@dataclass
class CloudPostureState:
    """Graph state for cloud security posture management pipeline."""

    # Input data — use last-value reducer for fields passed through unchanged
    cloud_accounts: Annotated[list[CloudAccount], _last_value] = field(default_factory=list)
    policy_rules: Annotated[list[PolicyRule], _last_value] = field(default_factory=list)
    iac_templates: Annotated[list[dict[str, Any]], _last_value] = field(default_factory=list)

    # Discovery stage
    resource_inventory: Annotated[list[CloudResource], _last_value] = field(default_factory=list)

    # Evaluation stages — additive from parallel branches
    policy_results: Annotated[list[PolicyFinding], operator.add] = field(default_factory=list)
    iac_scan_results: Annotated[list[IaCScanResult], operator.add] = field(default_factory=list)

    # Prioritization
    prioritized_findings: Annotated[list[PrioritizedFinding], _last_value] = field(default_factory=list)

    # Drift tracking
    drift_records: Annotated[list[DriftRecord], _last_value] = field(default_factory=list)
    previous_snapshot: Annotated[list[CloudResource], _last_value] = field(default_factory=list)

    # Compliance scoring
    compliance_scores: Annotated[dict[str, ComplianceScore], _merge_dicts] = field(default_factory=dict)

    # Publishing
    tickets_created: Annotated[dict[str, str], _merge_dicts] = field(default_factory=dict)
    alerts_sent: Annotated[list[str], operator.add] = field(default_factory=list)

    # Metadata
    processing_errors: Annotated[list[str], operator.add] = field(default_factory=list)
    metrics: Annotated[dict[str, Any], _merge_dicts] = field(default_factory=dict)
