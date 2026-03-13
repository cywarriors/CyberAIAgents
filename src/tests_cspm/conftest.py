"""Test configuration and fixtures for Cloud Security Posture Management Agent."""

import pytest
from datetime import datetime, timezone


@pytest.fixture
def sample_account_ids():
    """Sample cloud account IDs for testing."""
    return [
        "aws-prod-001",
        "aws-staging-001",
        "azure-prod-001",
        "gcp-prod-001",
        "gcp-dev-001",
    ]


@pytest.fixture
def sample_resource_types():
    """Sample cloud resource types for testing."""
    return [
        "s3_bucket",
        "rds_instance",
        "ec2_instance",
        "iam_user",
        "storage_account",
        "key_vault",
        "gcs_bucket",
        "compute_instance",
    ]
