"""Unit tests for Node 2 – DiscoverAssets."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from vapt_agent.nodes.discover_assets import discover_assets
from tests_vapt.mocks.generators import generate_valid_roe


class TestDiscoverAssets:
    """Test suite for asset discovery node."""

    def test_skips_when_roe_not_validated(self):
        result = discover_assets({"roe_validated": False, "roe_authorization": {}})
        assert "errors" in result
        assert len(result["errors"]) >= 1

    @patch("vapt_agent.nodes.discover_assets.run_nmap_scan")
    @patch("vapt_agent.nodes.discover_assets.lookup_asset", return_value=None)
    def test_returns_discovered_assets(self, _mock_cmdb, mock_nmap):
        mock_nmap.return_value = [
            {"ip": "10.0.1.10", "hostname": "h1.example.com", "os": "Ubuntu 22.04",
             "open_ports": [22, 80], "services": []},
            {"ip": "10.0.1.11", "hostname": "h2.example.com", "os": "CentOS 8",
             "open_ports": [443], "services": []},
        ]
        roe = generate_valid_roe()
        result = discover_assets({
            "roe_validated": True,
            "roe_authorization": roe,
            "engagement_id": "eng-01",
        })
        assets = result.get("discovered_assets", [])
        assert len(assets) == 2
        assert all("asset_id" in a for a in assets)

    @patch("vapt_agent.nodes.discover_assets.run_nmap_scan", return_value=[])
    def test_empty_scan_returns_empty_assets(self, _mock_nmap):
        roe = generate_valid_roe()
        result = discover_assets({
            "roe_validated": True,
            "roe_authorization": roe,
        })
        assert result.get("discovered_assets", []) == []

    def test_no_targets_returns_error(self):
        roe = generate_valid_roe()
        roe["scope_ips"] = []
        roe["scope_domains"] = []
        result = discover_assets({
            "roe_validated": True,
            "roe_authorization": roe,
        })
        assert "errors" in result
