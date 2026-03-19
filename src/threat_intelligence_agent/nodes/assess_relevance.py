"""Node: Assess organisational relevance of each IOC."""

from __future__ import annotations

from typing import Any

import structlog

from threat_intelligence_agent.config import get_settings

logger = structlog.get_logger(__name__)

# Sector → related keywords for industry matching
_SECTOR_KEYWORDS: dict[str, list[str]] = {
    "financial_services": ["banking", "finance", "payment", "swift", "credit", "fintech", "trading"],
    "healthcare": ["health", "medical", "pharma", "hospital", "patient", "hipaa"],
    "energy": ["energy", "power", "grid", "oil", "gas", "scada", "ics", "utility"],
    "government": ["government", "gov", "federal", "defense", "military", "agency"],
    "technology": ["technology", "saas", "cloud", "software", "dev", "code", "api"],
    "retail": ["retail", "ecommerce", "pos", "shopping", "consumer"],
    "manufacturing": ["manufacturing", "ot", "ics", "factory", "supply_chain"],
}

_REGION_MAP: dict[str, list[str]] = {
    "north_america": ["us", "usa", "canada", "north_america", "na"],
    "europe": ["eu", "europe", "uk", "germany", "france", "emea"],
    "asia_pacific": ["apac", "asia", "japan", "china", "india", "australia"],
    "middle_east": ["mena", "middle_east", "uae", "saudi", "israel"],
    "global": ["global", "worldwide"],
}


def _industry_match(ioc: dict[str, Any], org_industry: str) -> float:
    """Score 0-100 how well this IOC relates to our industry."""
    labels = [lbl.lower() for lbl in ioc.get("labels", [])]
    campaign = (ioc.get("campaign", "") or "").lower()
    actor = (ioc.get("actor", "") or "").lower()
    text = " ".join(labels + [campaign, actor])

    keywords = _SECTOR_KEYWORDS.get(org_industry, [])
    if not keywords:
        return 50.0  # neutral

    hits = sum(1 for kw in keywords if kw in text)
    if hits == 0:
        return 20.0
    return min(40.0 + hits * 20.0, 100.0)


def _geography_match(ioc: dict[str, Any], org_region: str) -> float:
    """Score 0-100 if the IOC targets our region."""
    labels = [lbl.lower() for lbl in ioc.get("labels", [])]
    text = " ".join(labels)

    region_kw = _REGION_MAP.get(org_region, [])
    if any(kw in text for kw in region_kw):
        return 90.0
    if "global" in text or "worldwide" in text:
        return 70.0
    return 30.0


def _attack_surface_match(ioc: dict[str, Any], org_assets: list[str]) -> float:
    """Score based on overlap between IOC kill-chain phases and our asset types."""
    kill_chain = ioc.get("kill_chain_phases", [])
    ioc_type = ioc.get("ioc_type", "")

    # Simple heuristic: certain IOC types are more relevant to certain assets
    type_relevance: dict[str, list[str]] = {
        "ip": ["cloud_infra", "web_apps", "endpoints"],
        "domain": ["web_apps", "cloud_infra", "endpoints"],
        "url": ["web_apps", "endpoints"],
        "hash_sha256": ["endpoints"],
        "hash_md5": ["endpoints"],
        "hash_sha1": ["endpoints"],
        "email": ["endpoints"],
    }
    relevant_assets = type_relevance.get(ioc_type, [])
    overlap = len(set(relevant_assets) & set(org_assets))
    if overlap == 0:
        return 30.0
    return min(40.0 + overlap * 20.0, 100.0)


def assess_relevance(state: dict[str, Any]) -> dict[str, Any]:
    """Compute organisational relevance scores for deduplicated IOCs."""
    iocs: list[dict[str, Any]] = state.get("deduplicated_iocs", [])
    settings = get_settings()
    org_assets = [a.strip() for a in settings.org_asset_types.split(",")]

    assessments: list[dict[str, Any]] = []

    for ioc in iocs:
        ind_score = _industry_match(ioc, settings.org_industry)
        geo_score = _geography_match(ioc, settings.org_region)
        surface_score = _attack_surface_match(ioc, org_assets)
        historical_score = 50.0  # placeholder

        relevance = round(
            ind_score * settings.relevance_industry_weight
            + geo_score * settings.relevance_geography_weight
            + surface_score * settings.relevance_attack_surface_weight
            + historical_score * settings.relevance_historical_weight,
            2,
        )

        parts: list[str] = []
        if ind_score >= 60:
            parts.append("industry-relevant")
        if geo_score >= 60:
            parts.append("geography-relevant")
        if surface_score >= 60:
            parts.append("attack-surface overlap")

        assessments.append(
            {
                "ioc_id": ioc.get("ioc_id", ""),
                "value": ioc.get("value", ""),
                "relevance": relevance,
                "industry_score": round(ind_score, 2),
                "geography_score": round(geo_score, 2),
                "attack_surface_score": round(surface_score, 2),
                "historical_score": round(historical_score, 2),
                "explanation": "; ".join(parts) if parts else "baseline relevance",
            }
        )

    logger.info("assess_relevance.done", count=len(assessments))
    return {"relevance_assessments": assessments}
