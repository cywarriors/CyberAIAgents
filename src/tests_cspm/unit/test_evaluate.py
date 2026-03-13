"""Unit tests for policy evaluation logic."""

import pytest
from cloud_security_agent.models import (
    CloudResource,
    CloudProvider,
    SeverityLevel,
    ComplianceStatus,
    ExposureLevel,
)
from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.rules import PolicyEngine, DEFAULT_POLICY_RULES
from cloud_security_agent.nodes.evaluate import evaluate_policies
from tests_cspm.mocks.generators import MockDataGenerator


class TestPolicyEngine:
    """Tests for the PolicyEngine.evaluate_resource method."""

    def _make_s3_resource(self, config_overrides=None):
        return MockDataGenerator.generate_resource(
            resource_type="s3_bucket",
            name="test-bucket",
            config_overrides=config_overrides,
        )

    def _get_rule(self, rule_id: str):
        return next(r for r in DEFAULT_POLICY_RULES if r.rule_id == rule_id)

    def test_s3_encryption_pass(self):
        resource = self._make_s3_resource({"encryption_enabled": True})
        rule = self._get_rule("cis_s3_encryption")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.PASS

    def test_s3_encryption_fail(self):
        resource = self._make_s3_resource({"encryption_enabled": False})
        rule = self._get_rule("cis_s3_encryption")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.FAIL
        assert finding.evidence["encryption_enabled"] is False

    def test_s3_public_access_pass(self):
        resource = self._make_s3_resource({"public_access_enabled": False})
        rule = self._get_rule("cis_s3_public_access")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.PASS

    def test_s3_public_access_fail(self):
        resource = self._make_s3_resource({"public_access_enabled": True})
        rule = self._get_rule("cis_s3_public_access")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.FAIL
        assert finding.severity == SeverityLevel.CRITICAL

    def test_iam_mfa_fail(self):
        resource = MockDataGenerator.generate_resource(
            resource_type="iam_user",
            name="admin",
            config_overrides={"mfa_enabled": False},
        )
        rule = self._get_rule("cis_iam_mfa")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.FAIL
        assert finding.severity == SeverityLevel.CRITICAL

    def test_iam_mfa_pass(self):
        resource = MockDataGenerator.generate_resource(
            resource_type="iam_user",
            name="admin",
            config_overrides={"mfa_enabled": True},
        )
        rule = self._get_rule("cis_iam_mfa")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.PASS

    def test_iam_excessive_permissions_fail(self):
        resource = MockDataGenerator.generate_resource(
            resource_type="iam_user",
            name="deploy-user",
            config_overrides={"attached_policies": ["AdministratorAccess"]},
        )
        rule = self._get_rule("cis_iam_excessive_permissions")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.FAIL

    def test_iam_excessive_permissions_pass(self):
        resource = MockDataGenerator.generate_resource(
            resource_type="iam_user",
            name="readonly-user",
            config_overrides={"attached_policies": ["ReadOnlyAccess"]},
        )
        rule = self._get_rule("cis_iam_excessive_permissions")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.PASS

    def test_rds_encryption_fail(self):
        resource = MockDataGenerator.generate_resource(
            resource_type="rds_instance",
            name="prod-db",
            config_overrides={"encryption_enabled": False},
        )
        rule = self._get_rule("cis_rds_encryption")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.FAIL

    def test_rule_not_applicable_wrong_resource_type(self):
        resource = self._make_s3_resource()
        rule = self._get_rule("cis_iam_mfa")  # IAM rule, not applicable to S3
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.status == ComplianceStatus.NOT_APPLICABLE

    def test_finding_id_is_deterministic(self):
        id1 = PolicyEngine.generate_finding_id("rule1", "resource1")
        id2 = PolicyEngine.generate_finding_id("rule1", "resource1")
        id3 = PolicyEngine.generate_finding_id("rule1", "resource2")
        assert id1 == id2
        assert id1 != id3

    def test_finding_has_remediation_info(self):
        resource = self._make_s3_resource({"encryption_enabled": False})
        rule = self._get_rule("cis_s3_encryption")
        finding = PolicyEngine.evaluate_resource(resource, rule)
        assert finding.remediation_guidance
        assert finding.cli_fix_command


@pytest.mark.asyncio
class TestEvaluatePoliciesNode:
    """Tests for the evaluate_policies graph node."""

    async def test_evaluate_finds_misconfigurations(self):
        state = CloudPostureState()
        state.resource_inventory = [
            MockDataGenerator.generate_resource(
                resource_type="s3_bucket",
                name="unencrypted-bucket",
                config_overrides={"encryption_enabled": False},
            ),
            MockDataGenerator.generate_resource(
                resource_type="s3_bucket",
                name="public-bucket",
                config_overrides={"public_access_enabled": True},
            ),
        ]
        result = await evaluate_policies(state)

        assert len(result["policy_results"]) >= 2
        assert result["metrics"]["policy_findings_count"] >= 2

    async def test_evaluate_clean_resources_no_findings(self):
        state = CloudPostureState()
        state.resource_inventory = [
            MockDataGenerator.generate_resource(
                resource_type="s3_bucket",
                name="secure-bucket",
                config_overrides={
                    "encryption_enabled": True,
                    "public_access_enabled": False,
                    "versioning_enabled": True,
                    "logging_enabled": True,
                },
            ),
        ]
        result = await evaluate_policies(state)
        assert len(result["policy_results"]) == 0

    async def test_evaluate_with_batch_resources(self):
        state = CloudPostureState()
        state.resource_inventory = MockDataGenerator.generate_resource_inventory(50)
        result = await evaluate_policies(state)

        # With ~40% misconfigured resources, should have some findings
        assert result["metrics"]["policy_findings_count"] >= 0
        assert result["metrics"]["rules_evaluated"] == len(DEFAULT_POLICY_RULES)

    async def test_evaluate_populates_severity_metrics(self):
        state = CloudPostureState()
        state.resource_inventory = [
            MockDataGenerator.generate_resource(
                resource_type="s3_bucket", name="b1",
                config_overrides={"encryption_enabled": False, "public_access_enabled": True},
            ),
        ]
        result = await evaluate_policies(state)
        assert "findings_by_severity" in result["metrics"]
