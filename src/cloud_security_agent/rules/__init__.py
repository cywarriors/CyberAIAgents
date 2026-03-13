"""Policy rules engine for cloud security compliance evaluation."""

from cloud_security_agent.models import (
    CloudResource,
    PolicyFinding,
    PolicyRule,
    SeverityLevel,
    ComplianceStatus,
    CloudProvider,
    ExposureLevel,
)
from datetime import datetime, timezone
import hashlib


class PolicyEngine:
    """Engine for evaluating cloud resources against security policies."""

    @staticmethod
    def generate_finding_id(rule_id: str, resource_id: str) -> str:
        """Generate a deterministic finding ID."""
        raw = f"{rule_id}:{resource_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def evaluate_resource(resource: CloudResource, rule: PolicyRule) -> PolicyFinding:
        """Evaluate a single resource against a security policy rule."""
        config = resource.configuration
        status = ComplianceStatus.PASS
        evidence: dict = {}

        # Check if rule applies to this resource type
        if resource.resource_type not in rule.resource_types:
            return PolicyFinding(
                finding_id=PolicyEngine.generate_finding_id(rule.rule_id, resource.resource_id),
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                resource_name=resource.resource_name,
                account_id=resource.account_id,
                provider=resource.provider,
                region=resource.region,
                status=ComplianceStatus.NOT_APPLICABLE,
                severity=rule.severity,
                framework=rule.framework,
                control_id=rule.control_id,
                description=rule.description,
            )

        # Evaluate based on rule type
        if "encryption" in rule.rule_id.lower():
            encrypted = config.get("encryption_enabled", False)
            if not encrypted:
                status = ComplianceStatus.FAIL
                evidence = {"encryption_enabled": False, "expected": True}

        elif "public_access" in rule.rule_id.lower():
            public = config.get("public_access_enabled", False)
            if public:
                status = ComplianceStatus.FAIL
                evidence = {"public_access_enabled": True, "expected": False}

        elif "logging" in rule.rule_id.lower():
            logging_enabled = config.get("logging_enabled", False)
            if not logging_enabled:
                status = ComplianceStatus.FAIL
                evidence = {"logging_enabled": False, "expected": True}

        elif "mfa" in rule.rule_id.lower():
            mfa_enabled = config.get("mfa_enabled", False)
            if not mfa_enabled:
                status = ComplianceStatus.FAIL
                evidence = {"mfa_enabled": False, "expected": True}

        elif "versioning" in rule.rule_id.lower():
            versioning = config.get("versioning_enabled", False)
            if not versioning:
                status = ComplianceStatus.FAIL
                evidence = {"versioning_enabled": False, "expected": True}

        elif "tls" in rule.rule_id.lower() or "ssl" in rule.rule_id.lower():
            tls_version = config.get("tls_version", "")
            if tls_version < "1.2":
                status = ComplianceStatus.FAIL
                evidence = {"tls_version": tls_version, "minimum_required": "1.2"}

        elif "iam_excessive" in rule.rule_id.lower():
            policies = config.get("attached_policies", [])
            has_admin = any("AdministratorAccess" in p for p in policies)
            if has_admin:
                status = ComplianceStatus.FAIL
                evidence = {"admin_access_attached": True, "policies": policies}

        elif "rotation" in rule.rule_id.lower():
            rotation_days = config.get("key_rotation_days", 999)
            if rotation_days > 90:
                status = ComplianceStatus.FAIL
                evidence = {"key_rotation_days": rotation_days, "max_allowed": 90}

        now = datetime.now(timezone.utc)
        return PolicyFinding(
            finding_id=PolicyEngine.generate_finding_id(rule.rule_id, resource.resource_id),
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            resource_name=resource.resource_name,
            account_id=resource.account_id,
            provider=resource.provider,
            region=resource.region,
            status=status,
            severity=rule.severity,
            framework=rule.framework,
            control_id=rule.control_id,
            description=rule.description,
            evidence=evidence,
            remediation_guidance=rule.remediation_guidance,
            iac_fix_snippet=rule.iac_fix_template,
            cli_fix_command=rule.cli_fix_command,
            first_detected=now,
            last_evaluated=now,
        )


# Default CIS/NIST policy rule set
DEFAULT_POLICY_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="cis_s3_encryption",
        rule_name="S3 Bucket Server-Side Encryption",
        description="S3 buckets must have server-side encryption enabled",
        framework="CIS",
        control_id="CIS 2.1.1",
        severity=SeverityLevel.HIGH,
        resource_types=["s3_bucket"],
        providers=[CloudProvider.AWS],
        remediation_guidance="Enable SSE-S3 or SSE-KMS encryption on the S3 bucket",
        iac_fix_template='resource "aws_s3_bucket_server_side_encryption_configuration" "example" {\n  bucket = aws_s3_bucket.example.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "aws:kms"\n    }\n  }\n}',
        cli_fix_command="aws s3api put-bucket-encryption --bucket BUCKET_NAME --server-side-encryption-configuration ...",
    ),
    PolicyRule(
        rule_id="cis_s3_public_access",
        rule_name="S3 Bucket Public Access Block",
        description="S3 buckets must not allow public access",
        framework="CIS",
        control_id="CIS 2.1.2",
        severity=SeverityLevel.CRITICAL,
        resource_types=["s3_bucket"],
        providers=[CloudProvider.AWS],
        remediation_guidance="Enable S3 Block Public Access settings",
        iac_fix_template='resource "aws_s3_bucket_public_access_block" "example" {\n  bucket = aws_s3_bucket.example.id\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}',
        cli_fix_command="aws s3api put-public-access-block --bucket BUCKET_NAME --public-access-block-configuration ...",
    ),
    PolicyRule(
        rule_id="cis_rds_encryption",
        rule_name="RDS Instance Encryption at Rest",
        description="RDS instances must have encryption at rest enabled",
        framework="CIS",
        control_id="CIS 2.3.1",
        severity=SeverityLevel.HIGH,
        resource_types=["rds_instance"],
        providers=[CloudProvider.AWS],
        remediation_guidance="Enable encryption at rest for RDS instance (requires recreation)",
        cli_fix_command="aws rds modify-db-instance --db-instance-identifier INSTANCE_ID --storage-encrypted",
    ),
    PolicyRule(
        rule_id="cis_iam_mfa",
        rule_name="IAM User MFA Enabled",
        description="IAM users with console access must have MFA enabled",
        framework="CIS",
        control_id="CIS 1.2",
        severity=SeverityLevel.CRITICAL,
        resource_types=["iam_user"],
        providers=[CloudProvider.AWS],
        remediation_guidance="Enable MFA for the IAM user",
        cli_fix_command="aws iam enable-mfa-device --user-name USERNAME --serial-number MFA_ARN --authentication-code-1 CODE1 --authentication-code-2 CODE2",
    ),
    PolicyRule(
        rule_id="cis_iam_excessive_permissions",
        rule_name="IAM Excessive Permissions",
        description="IAM roles and users should follow least-privilege principle",
        framework="CIS",
        control_id="CIS 1.16",
        severity=SeverityLevel.HIGH,
        resource_types=["iam_user", "iam_role"],
        providers=[CloudProvider.AWS],
        remediation_guidance="Remove AdministratorAccess and apply least-privilege policies",
    ),
    PolicyRule(
        rule_id="cis_cloudtrail_logging",
        rule_name="CloudTrail Logging Enabled",
        description="CloudTrail must be enabled in all regions",
        framework="CIS",
        control_id="CIS 3.1",
        severity=SeverityLevel.HIGH,
        resource_types=["cloudtrail"],
        providers=[CloudProvider.AWS],
        remediation_guidance="Enable CloudTrail logging across all regions",
    ),
    PolicyRule(
        rule_id="nist_storage_encryption",
        rule_name="Storage Account Encryption",
        description="Storage accounts must use encryption at rest (AES-256)",
        framework="NIST",
        control_id="NIST SC-28",
        severity=SeverityLevel.HIGH,
        resource_types=["storage_account", "s3_bucket", "gcs_bucket"],
        providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
        remediation_guidance="Enable encryption with AES-256 or customer-managed keys",
    ),
    PolicyRule(
        rule_id="nist_tls_version",
        rule_name="Minimum TLS Version 1.2",
        description="All services must enforce TLS 1.2 or higher",
        framework="NIST",
        control_id="NIST SC-8",
        severity=SeverityLevel.HIGH,
        resource_types=["load_balancer", "api_gateway", "app_service"],
        providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
        remediation_guidance="Update minimum TLS version to 1.2",
    ),
    PolicyRule(
        rule_id="nist_key_rotation",
        rule_name="Encryption Key Rotation",
        description="Encryption keys must be rotated within 90 days",
        framework="NIST",
        control_id="NIST SC-12",
        severity=SeverityLevel.MEDIUM,
        resource_types=["kms_key", "key_vault_key"],
        providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
        remediation_guidance="Enable automatic key rotation with maximum 90-day period",
    ),
    PolicyRule(
        rule_id="cis_db_public_access",
        rule_name="Database Public Access Disabled",
        description="Database instances must not be publicly accessible",
        framework="CIS",
        control_id="CIS 2.3.2",
        severity=SeverityLevel.CRITICAL,
        resource_types=["rds_instance", "sql_database", "cloud_sql"],
        providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
        remediation_guidance="Disable public accessibility on database instances",
    ),
    PolicyRule(
        rule_id="cis_vm_public_access",
        rule_name="VM Public IP Restrictions",
        description="Virtual machines should not have public IP addresses unless required",
        framework="CIS",
        control_id="CIS 4.1.1",
        severity=SeverityLevel.HIGH,
        resource_types=["ec2_instance", "virtual_machine", "compute_instance"],
        providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
        remediation_guidance="Remove public IP or place behind load balancer",
    ),
    PolicyRule(
        rule_id="cis_storage_versioning",
        rule_name="Storage Bucket Versioning",
        description="Storage buckets should have versioning enabled for data protection",
        framework="CIS",
        control_id="CIS 2.1.3",
        severity=SeverityLevel.MEDIUM,
        resource_types=["s3_bucket", "storage_account", "gcs_bucket"],
        providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
        remediation_guidance="Enable versioning on storage buckets",
    ),
]
