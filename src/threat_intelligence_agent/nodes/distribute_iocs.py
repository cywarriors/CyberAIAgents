"""Node: Distribute high-confidence IOCs to detection tools (SIEM, EDR, firewall)."""

from __future__ import annotations

from typing import Any

import structlog

from threat_intelligence_agent.config import get_settings
from threat_intelligence_agent.integrations.siem import publish_iocs_to_siem
from threat_intelligence_agent.integrations.edr import push_iocs_to_edr
from threat_intelligence_agent.integrations.firewall import push_blocklist_to_firewall

logger = structlog.get_logger(__name__)


def distribute_iocs(state: dict[str, Any]) -> dict[str, Any]:
    """Push IOCs above the confidence threshold to SIEM, EDR, and firewall.

    IOCs marked TLP:RED are NEVER auto-distributed (SEC-01 / SRS §9).
    """
    iocs = state.get("deduplicated_iocs", [])
    scores = state.get("confidence_scores", [])
    settings = get_settings()

    score_map = {s["ioc_id"]: s.get("confidence", 0) for s in scores}
    threshold = settings.confidence_distribution_threshold

    # Filter: above threshold AND not TLP:RED
    distributable = [
        ioc
        for ioc in iocs
        if score_map.get(ioc.get("ioc_id", ""), 0) >= threshold
        and ioc.get("tlp", "TLP:GREEN") != "TLP:RED"
    ]

    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    if not distributable:
        logger.info("distribute_iocs.none_qualified", threshold=threshold)
        return {"distribution_results": results}

    # Prepare payload lists by IOC type
    ip_iocs = [i for i in distributable if i.get("ioc_type") in ("ip",)]
    domain_iocs = [i for i in distributable if i.get("ioc_type") in ("domain",)]
    hash_iocs = [i for i in distributable if i.get("ioc_type", "").startswith("hash_")]
    url_iocs = [i for i in distributable if i.get("ioc_type") in ("url",)]

    # SIEM — all IOC types
    try:
        count = publish_iocs_to_siem(distributable)
        results.append({"target": "siem", "ioc_count": count, "status": "ok"})
    except Exception as exc:
        logger.warning("distribute.siem_error", error=str(exc))
        errors.append({"node": "distribute_iocs", "target": "siem", "error": str(exc)})
        results.append({"target": "siem", "ioc_count": 0, "status": "error", "error": str(exc)})

    # EDR — primarily hashes and IPs
    edr_iocs = hash_iocs + ip_iocs
    if edr_iocs:
        try:
            count = push_iocs_to_edr(edr_iocs)
            results.append({"target": "edr", "ioc_count": count, "status": "ok"})
        except Exception as exc:
            logger.warning("distribute.edr_error", error=str(exc))
            errors.append({"node": "distribute_iocs", "target": "edr", "error": str(exc)})
            results.append({"target": "edr", "ioc_count": 0, "status": "error", "error": str(exc)})

    # Firewall — IPs, domains, URLs for blocklist
    fw_iocs = ip_iocs + domain_iocs + url_iocs
    if fw_iocs:
        try:
            count = push_blocklist_to_firewall(fw_iocs)
            results.append({"target": "firewall", "ioc_count": count, "status": "ok"})
        except Exception as exc:
            logger.warning("distribute.firewall_error", error=str(exc))
            errors.append({"node": "distribute_iocs", "target": "firewall", "error": str(exc)})
            results.append({"target": "firewall", "ioc_count": 0, "status": "error", "error": str(exc)})

    logger.info("distribute_iocs.done", distributed=len(distributable), targets=len(results))
    result: dict[str, Any] = {"distribution_results": results}
    if errors:
        result["processing_errors"] = errors
    return result
