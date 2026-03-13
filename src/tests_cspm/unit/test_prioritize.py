"""Unit tests for risk prioritization logic."""

import pytest
from cloud_security_agent.models import (
    SeverityLevel,
    ComplianceStatus,
    ExposureLevel,
    CloudProvider,
)
from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.nodes.prioritize import (
    get_severity_score,
    get_exposure_score,
    get_blast_radius_score,
    get_criticality_score,
    determine_blast_radius,
    prioritize_findings,
)
from tests_cspm.mocks.generators import MockDataGenerator


class TestScoringFunctions:
    """Tests for individual scoring helper functions."""

    def test_severity_scores(self):
        assert get_severity_score(SeverityLevel.CRITICAL) == 100
        assert get_severity_score(SeverityLevel.HIGH) == 75
        assert get_severity_score(SeverityLevel.MEDIUM) == 50
        assert get_severity_score(SeverityLevel.LOW) == 25
        assert get_severity_score(SeverityLevel.INFO) == 10

    def test_exposure_scores(self):
        assert get_exposure_score(ExposureLevel.PUBLIC) == 100
        assert get_exposure_score(ExposureLevel.INTERNET_FACING) == 80
        assert get_exposure_score(ExposureLevel.INTERNAL) == 40
        assert get_exposure_score(ExposureLevel.PRIVATE) == 20

    def test_blast_radius_scores(self):
        assert get_blast_radius_score("account-wide") == 100
        assert get_blast_radius_score("region-wide") == 70
        assert get_blast_radius_score("service-wide") == 50
        assert get_blast_radius_score("resource-level") == 30
        # Unknown defaults to 30
        assert get_blast_radius_score("unknown") == 30

    def test_criticality_scores(self):
        assert get_criticality_score("critical") == 100
        assert get_criticality_score("high") == 75
        assert get_criticality_score("medium") == 50
        assert get_criticality_score("low") == 25
        assert get_criticality_score("Critical") == 100  # case insensitive

    def test_blast_radius_iam_is_account_wide(self):
        assert determine_blast_radius("iam_user", "cis_iam_mfa") == "account-wide"
        assert determine_blast_radius("iam_role", "iam_excessive") == "account-wide"

    def test_blast_radius_network_is_region_wide(self):
        assert determine_blast_radius("security_group", "sg_open") == "region-wide"
        assert determine_blast_radius("vpc", "vpc_flow_logs") == "region-wide"

    def test_blast_radius_logging_is_service_wide(self):
        assert determine_blast_radius("cloudtrail", "cis_logging") == "service-wide"

    def test_blast_radius_default_is_resource_level(self):
        assert determine_blast_radius("s3_bucket", "cis_s3_encryption") == "resource-level"
        assert determine_blast_radius("rds_instance", "cis_rds_encryption") == "resource-level"


@pytest.mark.asyncio
class TestPrioritizeNode:
    """Tests for the prioritize_findings graph node."""

    async def test_prioritize_sorts_by_score_descending(self):
        state = CloudPostureState()
        # Add mixed severity findings
        findings = []
        for sev in [SeverityLevel.LOW, SeverityLevel.CRITICAL, SeverityLevel.MEDIUM]:
            f = MockDataGenerator.generate_policy_finding(severity=sev)
            findings.append(f)

        state.policy_results = findings
        state.resource_inventory = [
            MockDataGenerator.generate_resource(
                resource_type="s3_bucket",
                name=f"bucket-{i}",
                exposure=ExposureLevel.PUBLIC,
                criticality="critical",
            )
            for i in range(5)
        ]

        result = await prioritize_findings(state)

        assert len(result.prioritized_findings) > 0
        scores = [f.composite_risk_score for f in result.prioritized_findings]
        assert scores == sorted(scores, reverse=True)

    async def test_prioritize_caps_at_100(self):
        state = CloudPostureState()
        # Max everything: critical severity + public exposure + account-wide blast + critical asset
        f = MockDataGenerator.generate_policy_finding(severity=SeverityLevel.CRITICAL)
        f.resource_type = "iam_user"
        f.rule_id = "cis_iam_mfa"
        state.policy_results = [f]
        state.resource_inventory = [
            MockDataGenerator.generate_resource(
                resource_type="iam_user",
                name="admin",
                exposure=ExposureLevel.PUBLIC,
                criticality="critical",
            )
        ]

        result = await prioritize_findings(state)
        for pf in result.prioritized_findings:
            assert pf.composite_risk_score <= 100.0

    async def test_prioritize_populates_metrics(self):
        state = CloudPostureState()
        state.policy_results = MockDataGenerator.generate_findings_batch(10)
        state.resource_inventory = MockDataGenerator.generate_resource_inventory(20)

        result = await prioritize_findings(state)

        assert "prioritized_count" in result.metrics
        assert "critical_findings" in result.metrics
        assert "high_findings" in result.metrics
        assert "medium_findings" in result.metrics
        assert "low_findings" in result.metrics

    async def test_prioritize_generates_explanation(self):
        state = CloudPostureState()
        state.policy_results = [MockDataGenerator.generate_policy_finding()]
        state.resource_inventory = MockDataGenerator.generate_resource_inventory(10)

        result = await prioritize_findings(state)

        if result.prioritized_findings:
            pf = result.prioritized_findings[0]
            assert pf.risk_explanation
            assert "Severity" in pf.risk_explanation
            assert "Exposure" in pf.risk_explanation

    async def test_prioritize_empty_findings(self):
        state = CloudPostureState()
        state.policy_results = []
        state.resource_inventory = []

        result = await prioritize_findings(state)
        assert len(result.prioritized_findings) == 0
        assert result.metrics["prioritized_count"] == 0

    async def test_prioritize_skips_pass_findings(self):
        state = CloudPostureState()
        f = MockDataGenerator.generate_policy_finding(status=ComplianceStatus.PASS)
        state.policy_results = [f]

        result = await prioritize_findings(state)
        assert len(result.prioritized_findings) == 0
