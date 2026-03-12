"""Unit tests for Node 3 – ScanVulnerabilities."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from vapt_agent.nodes.scan_vulnerabilities import scan_vulnerabilities
from tests_vapt.mocks.generators import generate_discovered_assets


class TestScanVulnerabilities:
    """Test suite for vulnerability scanning node."""

    def test_skips_when_roe_not_validated(self):
        result = scan_vulnerabilities({"roe_validated": False})
        assert "errors" in result

    def test_skips_when_no_assets(self):
        result = scan_vulnerabilities({
            "roe_validated": True,
            "discovered_assets": [],
        })
        assert "errors" in result

    @patch("vapt_agent.nodes.scan_vulnerabilities.run_zap_scan", return_value=[])
    @patch("vapt_agent.nodes.scan_vulnerabilities.run_nessus_scan", return_value=[])
    @patch("vapt_agent.nodes.scan_vulnerabilities.run_nuclei_scan")
    @patch("vapt_agent.nodes.scan_vulnerabilities.enrich_cve")
    def test_processes_nuclei_findings(self, mock_enrich, mock_nuclei, _nessus, _zap):
        mock_nuclei.return_value = [
            {
                "asset_id": "a1",
                "scanner": "nuclei",
                "cve_id": "CVE-2023-12345",
                "cwe_id": "CWE-89",
                "title": "SQL Injection in login form",
                "severity": "critical",
                "cvss_score": 9.8,
            }
        ]
        mock_enrich.return_value = {
            "cve_id": "CVE-2023-12345",
            "cvss_score": 9.8,
            "epss_score": 0.85,
            "in_kev": True,
        }

        assets = generate_discovered_assets(2)
        result = scan_vulnerabilities({
            "roe_validated": True,
            "discovered_assets": assets,
            "engagement_id": "eng-test",
        })
        findings = result.get("scan_results", [])
        assert len(findings) == 1
        assert findings[0]["cve_id"] == "CVE-2023-12345"
        assert findings[0]["severity"] == "critical"

    @patch("vapt_agent.nodes.scan_vulnerabilities.run_zap_scan", return_value=[])
    @patch("vapt_agent.nodes.scan_vulnerabilities.run_nessus_scan", return_value=[])
    @patch("vapt_agent.nodes.scan_vulnerabilities.run_nuclei_scan", return_value=[])
    def test_no_findings_returns_empty(self, _nuclei, _nessus, _zap):
        assets = generate_discovered_assets(1)
        result = scan_vulnerabilities({
            "roe_validated": True,
            "discovered_assets": assets,
        })
        assert result.get("scan_results", []) == []
