"""Integration tests for the full vulnerability management pipeline."""

import pytest
from vulnerability_mgmt_agent.models.state import VulnMgmtState
from vulnerability_mgmt_agent.graph import vuln_mgmt_graph
from tests_vm.mocks.generators import MockDataGenerator


@pytest.mark.asyncio
async def test_full_pipeline_with_findings():
    """Test the complete vulnerability management pipeline."""
    
    # Generate test data
    findings = MockDataGenerator.generate_findings_batch(20)
    
    # Create enrichment data
    enriched_cve = {}
    for finding in findings:
        enriched_cve[finding.cve_id] = MockDataGenerator.generate_cve_enrichment()
    
    # Create asset profiles
    asset_profiles = {}
    for finding in findings:
        if finding.affected_asset_id not in asset_profiles:
            asset_profiles[finding.affected_asset_id] = MockDataGenerator.generate_asset_profile(
                finding.affected_asset_id
            )
    
    # Create initial state
    initial_state = VulnMgmtState()
    initial_state.scanner_findings = findings
    initial_state.enriched_cve_data = enriched_cve
    initial_state.asset_profiles = asset_profiles
    
    # Run pipeline
    result = await vuln_mgmt_graph.ainvoke(initial_state)
    
    # Handle both dict and state object returns
    findings_result = result.get("scanner_findings") if isinstance(result, dict) else result.scanner_findings
    assert len(findings_result) == 20, "Should preserve all input findings"
    
    dedup = result.get("deduplicated_findings") if isinstance(result, dict) else result.deduplicated_findings
    assert len(dedup) > 0, "Should have deduplicated findings"
    
    enriched = result.get("enriched_findings") if isinstance(result, dict) else result.enriched_findings
    assert len(enriched) > 0, "Should have enriched findings"
    
    scored = result.get("risk_scores") if isinstance(result, dict) else result.risk_scores
    assert len(scored) > 0, "Should have risk scored findings"
    
    remediation = result.get("remediation_plan") if isinstance(result, dict) else result.remediation_plan
    assert len(remediation) > 0, "Should have remediation items"
    
    sla = result.get("sla_records") if isinstance(result, dict) else result.sla_records
    assert len(sla) > 0, "Should have SLA records"
    
    metrics = result.get("metrics") if isinstance(result, dict) else result.metrics
    assert "critical_count" in metrics, "Should have critical count metric"
    assert "sla_compliance_percent" in metrics, "Should have SLA compliance metric"


@pytest.mark.asyncio
async def test_pipeline_with_critical_findings():
    """Test pipeline with critical severity findings."""
    
    # Generate critical findings
    findings = []
    for i in range(5):
        finding = MockDataGenerator.generate_finding(severity="critical")
        findings.append(finding)
    
    # Enrich with high CVSS
    enriched_cve = {}
    for finding in findings:
        enriched_cve[finding.cve_id] = MockDataGenerator.generate_cve_enrichment(
            is_in_kev=True,
            cvss_score=9.5,
        )
    
    # Create asset profiles with critical criticality
    asset_profiles = {}
    for finding in findings:
        asset_profiles[finding.affected_asset_id] = MockDataGenerator.generate_asset_profile(
            finding.affected_asset_id,
            criticality="critical",
        )
    
    # Run pipeline
    initial_state = VulnMgmtState()
    initial_state.scanner_findings = findings
    initial_state.enriched_cve_data = enriched_cve
    initial_state.asset_profiles = asset_profiles
    
    result = await vuln_mgmt_graph.ainvoke(initial_state)
    
    # Handle both dict and state object returns
    metrics = result.get("metrics") if isinstance(result, dict) else result.metrics
    
    # Verify critical findings are identified
    assert metrics.get("critical_count", 0) > 0, "Should identify critical findings"
    
    sla = result.get("sla_records") if isinstance(result, dict) else result.sla_records
    assert len(sla) > 0, "Should assign SLAs"


@pytest.mark.asyncio
async def test_pipeline_empty_input():
    """Test pipeline with empty input."""
    
    initial_state = VulnMgmtState()
    initial_state.scanner_findings = []
    initial_state.enriched_cve_data = {}
    initial_state.asset_profiles = {}
    
    result = await vuln_mgmt_graph.ainvoke(initial_state)
    
    # Handle both dict and state object returns
    dedup = result.get("deduplicated_findings") if isinstance(result, dict) else result.deduplicated_findings
    assert len(dedup) == 0
    
    scored = result.get("risk_scores") if isinstance(result, dict) else result.risk_scores
    assert len(scored) == 0
    
    metrics = result.get("metrics") if isinstance(result, dict) else result.metrics
    assert metrics.get("critical_count", 0) == 0
