"""NVD / EPSS / KEV enrichment – augment scan findings with threat intel."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from vapt_agent.config import get_settings

logger = structlog.get_logger(__name__)


def enrich_cve(cve_id: str) -> dict[str, Any]:
    """Fetch CVE details from NVD, EPSS probability, and KEV listing."""
    settings = get_settings()
    result: dict[str, Any] = {"cve_id": cve_id}

    # NVD
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(
                f"{settings.nvd_api_url}/cves/2.0",
                params={"cveId": cve_id},
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_item = vulns[0].get("cve", {})
                metrics = cve_item.get("metrics", {})
                cvss31 = metrics.get("cvssMetricV31", [{}])
                if cvss31:
                    result["cvss_score"] = cvss31[0].get("cvssData", {}).get("baseScore")
                    result["cvss_vector"] = cvss31[0].get("cvssData", {}).get("vectorString")
    except httpx.HTTPError:
        logger.warning("nvd_lookup_failed", cve_id=cve_id)

    # EPSS
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                settings.epss_api_url,
                params={"cve": cve_id},
            )
            resp.raise_for_status()
            data = resp.json()
            entries = data.get("data", [])
            if entries:
                result["epss_score"] = float(entries[0].get("epss", 0.0))
                result["epss_percentile"] = float(entries[0].get("percentile", 0.0))
    except httpx.HTTPError:
        logger.warning("epss_lookup_failed", cve_id=cve_id)

    # KEV
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(settings.kev_catalog_url)
            resp.raise_for_status()
            catalog = resp.json()
            kev_cves = {v["cveID"] for v in catalog.get("vulnerabilities", [])}
            result["in_kev"] = cve_id in kev_cves
    except httpx.HTTPError:
        logger.warning("kev_lookup_failed", cve_id=cve_id)
        result["in_kev"] = False

    return result
