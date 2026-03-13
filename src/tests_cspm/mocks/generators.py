"""Mock data generators for CSPM Agent testing."""

import random
from datetime import datetime, timedelta, timezone
from cloud_security_agent.models import (
    CloudAccount,
    CloudResource,
    CloudProvider,
    SeverityLevel,
    ComplianceStatus,
    RemediationStatus,
    ExposureLevel,
    PolicyRule,
    PolicyFinding,
    IaCScanResult,
    IaCFramework,
    PrioritizedFinding,
    DriftRecord,
    ComplianceScore,
)


class MockDataGenerator:
    """Generate realistic production-like mock data for CSPM testing."""

    ACCOUNT_CONFIGS = [
        ("aws-prod-001", "AWS Production", CloudProvider.AWS, "prod", ["us-east-1", "us-west-2"]),
        ("aws-staging-001", "AWS Staging", CloudProvider.AWS, "staging", ["us-east-1"]),
        ("azure-prod-001", "Azure Production", CloudProvider.AZURE, "prod", ["eastus", "westus"]),
        ("gcp-prod-001", "GCP Production", CloudProvider.GCP, "prod", ["us-central1"]),
        ("gcp-dev-001", "GCP Development", CloudProvider.GCP, "dev", ["us-central1"]),
    ]

    RESOURCE_TYPES_BY_PROVIDER = {
        CloudProvider.AWS: [
            ("s3_bucket", "S3", ["app-data", "logs", "backups", "public-assets"]),
            ("rds_instance", "RDS", ["prod-db", "analytics-db", "reporting-db"]),
            ("ec2_instance", "EC2", ["web-server", "api-server", "worker"]),
            ("iam_user", "IAM", ["admin-user", "deploy-user", "ci-user"]),
        ],
        CloudProvider.AZURE: [
            ("storage_account", "Storage", ["prodstorage", "logstorage", "sharedstorage"]),
            ("key_vault", "KeyVault", ["prod-vault", "app-vault"]),
            ("vm", "VM", ["web-vm", "api-vm"]),
        ],
        CloudProvider.GCP: [
            ("gcs_bucket", "GCS", ["data-bucket", "export-bucket", "archive-bucket"]),
            ("compute_instance", "Compute", ["web-instance", "api-instance"]),
        ],
    }

    @staticmethod
    def generate_accounts(count: int = 5) -> list[CloudAccount]:
        """Generate cloud accounts."""
        accounts = []
        for i, (aid, name, provider, env, regions) in enumerate(MockDataGenerator.ACCOUNT_CONFIGS[:count]):
            accounts.append(CloudAccount(
                account_id=aid,
                account_name=name,
                provider=provider,
                environment=env,
                owner_email=f"team-{env}@example.com",
                regions=regions,
                tags={"environment": env, "team": "security"},
            ))
        return accounts

    @staticmethod
    def generate_resource(
        account_id: str = "aws-prod-001",
        provider: CloudProvider = CloudProvider.AWS,
        resource_type: str = "s3_bucket",
        name: str = "test-bucket",
        region: str = "us-east-1",
        config_overrides: dict | None = None,
        exposure: ExposureLevel = ExposureLevel.PRIVATE,
        criticality: str = "medium",
    ) -> CloudResource:
        """Generate a single cloud resource."""
        default_configs = {
            "s3_bucket": {"encryption_enabled": True, "public_access_enabled": False, "versioning_enabled": True, "logging_enabled": True},
            "rds_instance": {"encryption_enabled": True, "public_access_enabled": False, "multi_az": True, "backup_retention_days": 7},
            "ec2_instance": {"encryption_enabled": True, "public_ip": False, "imdsv2_required": True},
            "iam_user": {"mfa_enabled": True, "attached_policies": ["ReadOnlyAccess"], "last_login_days_ago": 10},
            "storage_account": {"encryption_enabled": True, "public_access_enabled": False, "tls_version": "1.2"},
            "key_vault": {"encryption_enabled": True, "key_rotation_days": 60},
            "gcs_bucket": {"encryption_enabled": True, "public_access_enabled": False, "versioning_enabled": True},
            "compute_instance": {"encryption_enabled": True, "public_ip": False},
            "vm": {"encryption_enabled": True, "public_ip": False},
        }
        config = default_configs.get(resource_type, {})
        if config_overrides:
            config.update(config_overrides)

        return CloudResource(
            resource_id=f"{account_id}-{resource_type}-{name}",
            resource_arn=f"arn:{provider.value}:{resource_type}:{region}:{account_id}:{name}",
            resource_type=resource_type,
            resource_name=name,
            provider=provider,
            account_id=account_id,
            region=region,
            configuration=config,
            tags={"environment": "prod", "owner": "security-team"},
            exposure=exposure,
            criticality=criticality,
        )

    @staticmethod
    def generate_resource_inventory(count: int = 30) -> list[CloudResource]:
        """Generate a realistic multi-cloud resource inventory."""
        resources = []
        accounts = MockDataGenerator.ACCOUNT_CONFIGS

        for _ in range(count):
            acct = random.choice(accounts)
            aid, _, provider, env, regions = acct
            region = random.choice(regions)
            type_options = MockDataGenerator.RESOURCE_TYPES_BY_PROVIDER.get(provider, [])
            if not type_options:
                continue
            rtype, _, names = random.choice(type_options)
            name = random.choice(names)

            # Randomly introduce misconfigurations (~40% of resources)
            config_overrides = None
            exposure = ExposureLevel.PRIVATE
            if random.random() < 0.4:
                config_overrides = {}
                misconfig_type = random.choice(["no_encryption", "public_access", "no_mfa", "no_logging", "weak_tls", "admin_access"])
                if misconfig_type == "no_encryption":
                    config_overrides["encryption_enabled"] = False
                elif misconfig_type == "public_access":
                    config_overrides["public_access_enabled"] = True
                    exposure = ExposureLevel.PUBLIC
                elif misconfig_type == "no_mfa":
                    config_overrides["mfa_enabled"] = False
                elif misconfig_type == "no_logging":
                    config_overrides["logging_enabled"] = False
                elif misconfig_type == "weak_tls":
                    config_overrides["tls_version"] = "1.0"
                elif misconfig_type == "admin_access":
                    config_overrides["attached_policies"] = ["AdministratorAccess", "ReadOnlyAccess"]

            criticality = random.choice(["critical", "high", "medium", "low"])
            resources.append(MockDataGenerator.generate_resource(
                account_id=aid,
                provider=provider,
                resource_type=rtype,
                name=f"{name}-{len(resources)}",
                region=region,
                config_overrides=config_overrides,
                exposure=exposure,
                criticality=criticality,
            ))
        return resources

    @staticmethod
    def generate_policy_finding(
        severity: SeverityLevel = SeverityLevel.HIGH,
        provider: CloudProvider = CloudProvider.AWS,
        status: ComplianceStatus = ComplianceStatus.FAIL,
    ) -> PolicyFinding:
        """Generate a single policy finding."""
        now = datetime.now(timezone.utc)
        idx = random.randint(100, 99999)
        return PolicyFinding(
            finding_id=f"finding-{idx}",
            rule_id=f"cis_s3_encryption",
            rule_name="S3 Bucket Server-Side Encryption",
            resource_id=f"aws-prod-001-s3-bucket-{idx}",
            resource_type="s3_bucket",
            resource_name=f"test-bucket-{idx}",
            account_id="aws-prod-001",
            provider=provider,
            region="us-east-1",
            status=status,
            severity=severity,
            framework="CIS",
            control_id="CIS 2.1.1",
            description="S3 bucket missing encryption",
            evidence={"encryption_enabled": False},
            remediation_guidance="Enable SSE-KMS",
            first_detected=now - timedelta(days=random.randint(1, 30)),
            last_evaluated=now,
        )

    @staticmethod
    def generate_findings_batch(count: int = 20) -> list[PolicyFinding]:
        """Generate a batch of findings with mixed severities."""
        findings = []
        severities = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]
        providers = [CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP]
        for i in range(count):
            findings.append(MockDataGenerator.generate_policy_finding(
                severity=random.choice(severities),
                provider=random.choice(providers),
            ))
        return findings

    @staticmethod
    def generate_drift_record(
        drift_type: str = "security_regression",
    ) -> DriftRecord:
        """Generate a drift record."""
        now = datetime.now(timezone.utc)
        idx = random.randint(100, 99999)
        return DriftRecord(
            drift_id=f"drift-{idx}",
            resource_id=f"aws-prod-001-s3-{idx}",
            resource_type="s3_bucket",
            account_id="aws-prod-001",
            provider=CloudProvider.AWS,
            field_changed="public_access_enabled",
            previous_value="False",
            current_value="True",
            drift_type=drift_type,
            detected_at=now,
        )

    @staticmethod
    def generate_iac_scan_result(
        failures: int = 3,
    ) -> IaCScanResult:
        """Generate an IaC scan result."""
        total = 20
        return IaCScanResult(
            scan_id=f"iac-scan-{random.randint(100, 999)}",
            template_path="infra/main.tf",
            framework=IaCFramework.TERRAFORM,
            repository="org/infra-repo",
            branch="main",
            findings=[MockDataGenerator.generate_policy_finding() for _ in range(failures)],
            total_resources=total,
            passed_checks=total - failures,
            failed_checks=failures,
            scan_duration_seconds=round(random.uniform(3.0, 15.0), 1),
        )

    @staticmethod
    def generate_compliance_score(
        account_id: str = "aws-prod-001",
        framework: str = "CIS",
        score: float = 85.0,
    ) -> ComplianceScore:
        """Generate a compliance score."""
        total = 120
        passed = int(total * score / 100)
        return ComplianceScore(
            account_id=account_id,
            framework=framework,
            total_controls=total,
            passed_controls=passed,
            failed_controls=total - passed,
            not_applicable_controls=0,
            score_percent=score,
            previous_score_percent=score - random.uniform(-5, 5),
            score_trend=random.choice(["improving", "stable", "declining"]),
        )
