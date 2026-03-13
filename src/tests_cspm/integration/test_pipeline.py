"""Integration tests for the full CSPM pipeline."""

import pytest
from cloud_security_agent.models import (
    CloudProvider,
    SeverityLevel,
    ExposureLevel,
)
from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.graph import cspm_graph
from cloud_security_agent.rules import DEFAULT_POLICY_RULES
from tests_cspm.mocks.generators import MockDataGenerator


def _get(result, key):
    """Handle both dict and state object returns from LangGraph."""
    return result.get(key) if isinstance(result, dict) else getattr(result, key)


@pytest.mark.asyncio
async def test_full_pipeline_with_misconfigured_resources():
    """Run the complete pipeline with a mix of compliant and non-compliant resources."""

    accounts = MockDataGenerator.generate_accounts(3)
    resources = MockDataGenerator.generate_resource_inventory(25)

    initial_state = CloudPostureState()
    initial_state.cloud_accounts = accounts
    initial_state.resource_inventory = resources
    initial_state.policy_rules = DEFAULT_POLICY_RULES

    result = await cspm_graph.ainvoke(initial_state)

    # Verify policy evaluation produced findings
    policy_results = _get(result, "policy_results")
    assert len(policy_results) > 0, "Should produce policy findings"

    # Verify prioritized findings
    prioritized = _get(result, "prioritized_findings")
    assert len(prioritized) > 0, "Should have prioritized findings"

    # Verify prioritized are sorted by score (descending)
    scores = [f.composite_risk_score for f in prioritized]
    assert scores == sorted(scores, reverse=True), "Should be sorted by risk score"

    # Verify metrics collected throughout pipeline
    metrics = _get(result, "metrics")
    assert "prioritized_count" in metrics
    assert "drift_total" in metrics


@pytest.mark.asyncio
async def test_pipeline_with_critical_misconfigurations():
    """Pipeline with resources that should trigger critical findings."""

    accounts = MockDataGenerator.generate_accounts(1)

    # Create deliberately misconfigured critical resources
    resources = [
        MockDataGenerator.generate_resource(
            name="public-unencrypted-bucket",
            resource_type="s3_bucket",
            exposure=ExposureLevel.PUBLIC,
            criticality="critical",
            config_overrides={
                "encryption_enabled": False,
                "public_access_enabled": True,
                "versioning_enabled": False,
                "logging_enabled": False,
            },
        ),
        MockDataGenerator.generate_resource(
            name="admin-no-mfa",
            resource_type="iam_user",
            exposure=ExposureLevel.INTERNAL,
            criticality="critical",
            config_overrides={
                "mfa_enabled": False,
                "attached_policies": ["AdministratorAccess"],
            },
        ),
    ]

    initial_state = CloudPostureState()
    initial_state.cloud_accounts = accounts
    initial_state.resource_inventory = resources
    initial_state.policy_rules = DEFAULT_POLICY_RULES

    result = await cspm_graph.ainvoke(initial_state)

    policy_results = _get(result, "policy_results")
    assert len(policy_results) > 0, "Misconfigurations should generate findings"

    prioritized = _get(result, "prioritized_findings")
    # At least one should be critical or high
    high_risk = [f for f in prioritized if f.composite_risk_score >= 60.0]
    assert len(high_risk) > 0, "Critical misconfigs should produce high-risk findings"


@pytest.mark.asyncio
async def test_pipeline_with_drift_detection():
    """Pipeline with previous snapshot to trigger drift detection."""

    current_resource = MockDataGenerator.generate_resource(
        name="drifted-bucket",
        config_overrides={"encryption_enabled": False, "public_access_enabled": True},
    )
    previous_resource = MockDataGenerator.generate_resource(
        name="drifted-bucket",
        config_overrides={"encryption_enabled": True, "public_access_enabled": False},
    )

    initial_state = CloudPostureState()
    initial_state.cloud_accounts = MockDataGenerator.generate_accounts(1)
    initial_state.resource_inventory = [current_resource]
    initial_state.previous_snapshot = [previous_resource]
    initial_state.policy_rules = DEFAULT_POLICY_RULES

    result = await cspm_graph.ainvoke(initial_state)

    drift = _get(result, "drift_records")
    assert len(drift) > 0, "Should detect configuration drift"

    metrics = _get(result, "metrics")
    assert metrics.get("drift_regressions", 0) > 0, "Should find security regressions"


@pytest.mark.asyncio
async def test_pipeline_empty_input():
    """Pipeline with no resources should complete without errors."""

    initial_state = CloudPostureState()
    initial_state.cloud_accounts = []
    initial_state.resource_inventory = []
    initial_state.policy_rules = []

    result = await cspm_graph.ainvoke(initial_state)

    policy_results = _get(result, "policy_results")
    assert len(policy_results) == 0

    prioritized = _get(result, "prioritized_findings")
    assert len(prioritized) == 0

    metrics = _get(result, "metrics")
    assert metrics.get("drift_total", 0) == 0


@pytest.mark.asyncio
async def test_pipeline_all_compliant_resources():
    """Pipeline where every resource passes all checks."""

    resources = [
        MockDataGenerator.generate_resource(
            name=f"compliant-{i}",
            resource_type="s3_bucket",
            config_overrides={
                "encryption_enabled": True,
                "public_access_enabled": False,
                "versioning_enabled": True,
                "logging_enabled": True,
            },
        )
        for i in range(5)
    ]

    initial_state = CloudPostureState()
    initial_state.cloud_accounts = MockDataGenerator.generate_accounts(1)
    initial_state.resource_inventory = resources
    initial_state.policy_rules = DEFAULT_POLICY_RULES

    result = await cspm_graph.ainvoke(initial_state)

    # All resources pass so prioritized findings should be empty
    prioritized = _get(result, "prioritized_findings")
    assert len(prioritized) == 0, "Compliant resources should produce zero prioritized findings"
