"""Node 2 – Discover Assets.

Enumerates hosts, open ports, and services within the authorised scope.
Implements FR-02 from SRS-13.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from vapt_agent.integrations.cmdb import lookup_asset
from vapt_agent.integrations.scanners import run_nmap_scan

logger = structlog.get_logger(__name__)


def discover_assets(state: dict[str, Any]) -> dict[str, Any]:
    """Run host/port enumeration and enrich with CMDB metadata."""
    if not state.get("roe_validated"):
        return {
            "errors": [{
                "node": "discover_assets",
                "message": "Skipped – RoE not validated.",
                "ts": datetime.now(timezone.utc).isoformat(),
            }]
        }

    roe = state.get("roe_authorization") or {}
    targets = list(roe.get("scope_ips", [])) + list(roe.get("scope_domains", []))

    if not targets:
        return {
            "errors": [{
                "node": "discover_assets",
                "message": "No targets in RoE scope.",
                "ts": datetime.now(timezone.utc).isoformat(),
            }]
        }

    raw_hosts = run_nmap_scan(targets)

    discovered: list[dict[str, Any]] = []
    for host in raw_hosts:
        asset_id = str(uuid.uuid4())
        ip = host.get("ip", "")
        hostname = host.get("hostname", "")

        # Enrich from CMDB
        cmdb_data = lookup_asset(ip=ip, hostname=hostname) or {}

        discovered.append({
            "asset_id": asset_id,
            "ip": ip,
            "hostname": hostname,
            "os_fingerprint": host.get("os", ""),
            "open_ports": host.get("open_ports", []),
            "services": host.get("services", []),
            "asset_type": cmdb_data.get("asset_type", "unknown"),
            "criticality": cmdb_data.get("criticality", "medium"),
            "cloud_provider": cmdb_data.get("cloud_provider"),
        })

    logger.info(
        "assets_discovered",
        engagement_id=state.get("engagement_id"),
        count=len(discovered),
    )
    return {"discovered_assets": discovered}
