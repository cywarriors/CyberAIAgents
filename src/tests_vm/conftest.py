"""Test configuration and fixtures."""

import pytest
from datetime import datetime


@pytest.fixture
def sample_cve_list():
    """Sample CVE IDs for testing."""
    return [
        "CVE-2023-1234",
        "CVE-2023-5678",
        "CVE-2023-9999",
        "CVE-2024-1111",
        "CVE-2024-2222",
    ]


@pytest.fixture
def sample_asset_ids():
    """Sample asset IDs for testing."""
    return [
        "prod-web-01",
        "prod-web-02",
        "prod-db-01",
        "staging-webapp",
        "dev-api-01",
    ]
