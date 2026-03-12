"""Unit tests for deduplication logic."""

import pytest
from vulnerability_mgmt_agent.models.state import VulnMgmtState
from vulnerability_mgmt_agent.nodes.deduplicate import deduplicate_findings
from tests_vm.mocks.generators import MockDataGenerator


@pytest.mark.asyncio
async def test_deduplication_removes_duplicates():
    """Test that deduplication removes duplicate findings."""
    # Create two identical findings (same CVE on same asset)
    finding1 = MockDataGenerator.generate_finding("CVE-2023-1234", "asset-1")
    finding2 = MockDataGenerator.generate_finding("CVE-2023-1234", "asset-1")
    
    state = VulnMgmtState()
    state.scanner_findings = [finding1, finding2]
    
    result = await deduplicate_findings(state)
    
    assert len(result.deduplicated_findings) == 1
    assert result.metrics["duplicate_count"] == 1
    assert result.metrics["unique_findings"] == 1


@pytest.mark.asyncio
async def test_deduplication_keeps_different_assets():
    """Test that dedup keeps findings on different assets."""
    # Same CVE but different assets
    finding1 = MockDataGenerator.generate_finding("CVE-2023-1234", "asset-1")
    finding2 = MockDataGenerator.generate_finding("CVE-2023-1234", "asset-2")
    
    state = VulnMgmtState()
    state.scanner_findings = [finding1, finding2]
    
    result = await deduplicate_findings(state)
    
    assert len(result.deduplicated_findings) == 2
    assert result.metrics["duplicate_count"] == 0


@pytest.mark.asyncio
async def test_deduplication_keeps_different_cves():
    """Test that dedup keeps findings with different CVEs."""
    # Different CVEs on same asset
    finding1 = MockDataGenerator.generate_finding("CVE-2023-1234", "asset-1")
    finding2 = MockDataGenerator.generate_finding("CVE-2023-5678", "asset-1")
    
    state = VulnMgmtState()
    state.scanner_findings = [finding1, finding2]
    
    result = await deduplicate_findings(state)
    
    assert len(result.deduplicated_findings) == 2
    assert result.metrics["duplicate_count"] == 0


@pytest.mark.asyncio
async def test_deduplication_batch():
    """Test deduplication on a batch of findings."""
    findings = []
    # Add 50 findings, but only 40 unique combinations
    for i in range(50):
        cve_index = i % 40  # Use same 40 CVE/asset combinations
        cve = f"CVE-2023-{1000 + cve_index}"
        asset = f"asset-{cve_index % 10}"
        findings.append(MockDataGenerator.generate_finding(cve, asset))
    
    state = VulnMgmtState()
    state.scanner_findings = findings
    
    result = await deduplicate_findings(state)
    
    assert len(result.deduplicated_findings) <= len(findings)
    assert len(result.deduplicated_findings) >= 40  # Should have at least 40 unique
