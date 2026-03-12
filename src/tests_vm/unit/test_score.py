"""Unit tests for risk scoring logic."""

import pytest
from vulnerability_mgmt_agent.nodes.score import normalize_cvss_score, get_criticality_multiplier, get_environment_multiplier
from vulnerability_mgmt_agent.models import SeverityTier
from tests_vm.mocks.generators import MockDataGenerator


def test_normalize_cvss_score():
    """Test CVSS score normalization."""
    assert normalize_cvss_score(10.0) == 1.0
    assert normalize_cvss_score(5.0) == 0.5
    assert normalize_cvss_score(0.0) == 0.0
    assert normalize_cvss_score(-1.0) == 0.0
    assert normalize_cvss_score(11.0) == 1.0


def test_criticality_multiplier():
    """Test asset criticality multiplier."""
    assert get_criticality_multiplier("critical") == 1.5
    assert get_criticality_multiplier("high") == 1.2
    assert get_criticality_multiplier("medium") == 1.0
    assert get_criticality_multiplier("low") == 0.8
    assert get_criticality_multiplier("unknown") == 1.0


def test_environment_multiplier():
    """Test environment multiplier."""
    assert get_environment_multiplier("prod") == 1.3
    assert get_environment_multiplier("production") == 1.3
    assert get_environment_multiplier("staging") == 0.8
    assert get_environment_multiplier("dev") == 0.5
    assert get_environment_multiplier("development") == 0.5


@pytest.mark.asyncio
async def test_score_calculation_high_cvss():
    """Test that high CVSS scores result in high risk tiers."""
    from vulnerability_mgmt_agent.models.state import VulnMgmtState
    from vulnerability_mgmt_agent.nodes.score import compute_risk_scores
    
    # Create finding with high CVSS
    finding = MockDataGenerator.generate_finding(severity="critical")
    finding.scanner_cvss = 9.5
    
    # Create enriched state
    enrichment = MockDataGenerator.generate_cve_enrichment(cvss_score=9.5, is_in_kev=True)
    asset = MockDataGenerator.generate_asset_profile(finding.affected_asset_id, "critical")
    # Set to production environment to maximize score
    asset.environment = "prod"
    
    scored = MockDataGenerator.generate_scored_finding()
    scored.finding = finding
    scored.cve_enrichment = enrichment
    scored.asset_profile = asset
    
    state = VulnMgmtState()
    state.enriched_findings = [scored]
    
    result = await compute_risk_scores(state)
    
    assert len(result.risk_scores) > 0
    # With CVSS 9.5, KEV, and critical asset, should be at least HIGH
    assert result.risk_scores[0].risk_tier in [SeverityTier.CRITICAL, SeverityTier.HIGH]


@pytest.mark.asyncio
async def test_score_calculation_kev_boost():
    """Test that KEV inclusion boosts risk score."""
    from vulnerability_mgmt_agent.models.state import VulnMgmtState
    from vulnerability_mgmt_agent.nodes.score import compute_risk_scores
    
    scored1 = MockDataGenerator.generate_scored_finding()
    scored1.cve_enrichment.is_in_kev = False
    
    scored2 = MockDataGenerator.generate_scored_finding()
    scored2.cve_enrichment.is_in_kev = True
    scored2.cve_enrichment.cvss_score = scored1.cve_enrichment.cvss_score
    
    state = VulnMgmtState()
    state.enriched_findings = [scored1, scored2]
    
    result = await compute_risk_scores(state)
    
    # KEV finding should have higher score
    assert result.risk_scores[0].composite_risk_score > result.risk_scores[1].composite_risk_score or \
           result.risk_scores[0].composite_risk_score == result.risk_scores[1].composite_risk_score


def test_mock_data_generation():
    """Test that mock data generators produce valid data."""
    finding = MockDataGenerator.generate_finding()
    assert finding.finding_id.startswith("finding_")
    assert finding.cve_id in MockDataGenerator.CVE_LIST or finding.cve_id.startswith("CVE-")
    assert finding.scanner_name in MockDataGenerator.SCANNERS
    
    enrichment = MockDataGenerator.generate_cve_enrichment()
    assert 0 <= enrichment.cvss_score <= 10.0
    assert 0 <= enrichment.epss_score <= 1.0
    
    asset = MockDataGenerator.generate_asset_profile()
    assert asset.criticality in ["critical", "high", "medium", "low"]
    assert asset.environment in MockDataGenerator.ENVIRONMENTS


def test_batch_generation():
    """Test batch data generation."""
    findings = MockDataGenerator.generate_findings_batch(50)
    assert len(findings) == 50
    
    scored = MockDataGenerator.generate_scored_findings_batch(30)
    assert len(scored) == 30
