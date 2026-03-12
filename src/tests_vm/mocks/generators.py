"""Mock data generators for testing."""

import random
from datetime import datetime, timedelta, timezone
from vulnerability_mgmt_agent.models import (
    Finding,
    CVEEnrichment,
    AssetProfile,
    ScoredFinding,
    SeverityTier,
)


class MockDataGenerator:
    """Generate realistic mock data for testing."""
    
    CVE_LIST = [
        "CVE-2023-1234", "CVE-2023-5678", "CVE-2023-9999",
        "CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333",
        "CVE-2023-4444", "CVE-2023-5555", "CVE-2024-6666",
    ]
    
    SCANNERS = ["Tenable", "Qualys", "Rapid7"]
    ASSET_TYPES = ["network", "endpoint", "container", "application"]
    SEVERITIES = ["critical", "high", "medium", "low"]
    BUSINESS_UNITS = ["Engineering", "Finance", "Operations", "Sales"]
    ENVIRONMENTS = ["prod", "staging", "dev"]
    
    @staticmethod
    def generate_finding(
        cve_id: str = None,
        asset_id: str = None,
        severity: str = None,
    ) -> Finding:
        """Generate a realistic finding."""
        
        if not cve_id:
            cve_id = random.choice(MockDataGenerator.CVE_LIST)
        if not asset_id:
            asset_id = f"asset-{random.randint(1, 100)}"
        if not severity:
            severity = random.choice(MockDataGenerator.SEVERITIES)
        
        finding_id = f"finding_{random.randint(10000, 99999)}"
        now = datetime.now(timezone.utc)
        
        return Finding(
            finding_id=finding_id,
            cve_id=cve_id,
            scanner_name=random.choice(MockDataGenerator.SCANNERS),
            scanner_finding_id=f"scan_{random.randint(1000, 9999)}",
            affected_asset_id=asset_id,
            title=f"Vulnerability in {cve_id}",
            description=f"Test description for {cve_id}",
            scanner_severity=severity,
            scanner_cvss=random.uniform(4.0, 10.0),
            evidence="Test evidence data",
            first_discovered=now - timedelta(days=random.randint(1, 30)),
            last_verified=now,
        )
    
    @staticmethod
    def generate_cve_enrichment(
        is_in_kev: bool = False,
        cvss_score: float = None,
    ) -> CVEEnrichment:
        """Generate CVE enrichment data."""
        
        if cvss_score is None:
            cvss_score = random.uniform(4.0, 10.0)
        
        return CVEEnrichment(
            cvss_score=cvss_score,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            epss_score=random.uniform(0.0, 1.0),
            epss_percentile=random.uniform(0.0, 100.0),
            is_in_kev=is_in_kev,
            exploit_available=random.choice([True, False]),
            exploit_verified=random.choice([True, False]) if is_in_kev else False,
            cwe_list=["CWE-79", "CWE-89"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                "https://www.exploit-db.com/exploits/12345",
            ],
            description="Test vulnerability description",
            published_date=datetime.now(timezone.utc) - timedelta(days=random.randint(1, 365)),
        )
    
    @staticmethod
    def generate_asset_profile(
        asset_id: str = None,
        criticality: str = None,
    ) -> AssetProfile:
        """Generate an asset profile."""
        
        if not asset_id:
            asset_id = f"asset-{random.randint(1, 100)}"
        if not criticality:
            criticality = random.choice(["critical", "high", "medium", "low"])
        
        return AssetProfile(
            asset_id=asset_id,
            asset_name=f"Server-{asset_id}",
            asset_type=random.choice(MockDataGenerator.ASSET_TYPES),
            criticality=criticality,
            environment=random.choice(MockDataGenerator.ENVIRONMENTS),
            business_unit=random.choice(MockDataGenerator.BUSINESS_UNITS),
            owner_email=f"owner-{random.randint(1, 50)}@example.com",
            data_classification="internal",
            ip_addresses=[f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"],
        )
    
    @staticmethod
    def generate_scored_finding() -> ScoredFinding:
        """Generate a scored finding with all enrichment."""
        
        finding = MockDataGenerator.generate_finding()
        enrichment = MockDataGenerator.generate_cve_enrichment()
        asset = MockDataGenerator.generate_asset_profile(finding.affected_asset_id)
        
        # Calculate a composite score for testing
        composite_score = (
            (enrichment.cvss_score / 10.0 * 35) +
            (enrichment.epss_score * 25) +
            (100 * 15 if enrichment.is_in_kev else 0) +
            (asset.criticality in ["critical", "high"] and 15 or 5)
        )
        
        risk_tier = SeverityTier.CRITICAL if composite_score >= 75 else (
            SeverityTier.HIGH if composite_score >= 55 else (
                SeverityTier.MEDIUM if composite_score >= 35 else SeverityTier.LOW
            )
        )
        
        return ScoredFinding(
            finding=finding,
            asset_profile=asset,
            cve_enrichment=enrichment,
            composite_risk_score=min(100.0, composite_score),
            risk_tier=risk_tier,
            risk_explanation=f"Risk score calculated from CVSS ({enrichment.cvss_score/10:.2f}), EPSS ({enrichment.epss_score:.2f}), and asset criticality ({asset.criticality})",
        )
    
    @staticmethod
    def generate_findings_batch(count: int = 50) -> list[Finding]:
        """Generate a batch of findings."""
        return [MockDataGenerator.generate_finding() for _ in range(count)]
    
    @staticmethod
    def generate_scored_findings_batch(count: int = 50) -> list[ScoredFinding]:
        """Generate a batch of scored findings."""
        return [MockDataGenerator.generate_scored_finding() for _ in range(count)]
