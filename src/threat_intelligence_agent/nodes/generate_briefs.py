"""Node: Generate intelligence briefs at strategic, operational, and tactical levels."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _build_tactical_brief(
    iocs: list[dict[str, Any]],
    scores: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
) -> dict[str, Any]:
    """IOC-focused brief for detection engineers and SOC analysts."""
    score_map = {s["ioc_id"]: s for s in scores}
    high_conf = [i for i in iocs if score_map.get(i.get("ioc_id", ""), {}).get("confidence", 0) >= 70]

    ioc_appendix = []
    for ioc in high_conf[:50]:
        sid = ioc.get("ioc_id", "")
        ioc_appendix.append(
            {
                "ioc_id": sid,
                "type": ioc.get("ioc_type", ""),
                "value": ioc.get("value", ""),
                "confidence": score_map.get(sid, {}).get("confidence", 0),
                "sources": ioc.get("sources", []),
            }
        )

    technique_ids = list({m["technique_id"] for m in mappings if m.get("technique_id")})

    return {
        "brief_id": f"brief-tac-{uuid.uuid4().hex[:8]}",
        "level": "tactical",
        "title": "Tactical IOC Feed — High-Confidence Indicators",
        "executive_summary": f"{len(high_conf)} high-confidence IOCs ready for operationalization.",
        "technical_analysis": (
            f"Total IOCs after deduplication: {len(iocs)}. "
            f"High-confidence (≥70): {len(high_conf)}. "
            f"Mapped to {len(technique_ids)} ATT&CK techniques."
        ),
        "ioc_appendix": ioc_appendix,
        "attck_mapping": [{"technique_id": tid} for tid in technique_ids[:20]],
        "recommendations": [
            "Ingest high-confidence IOCs into SIEM detection rules.",
            "Block critical IP/domain IOCs at perimeter firewall.",
            "Update EDR watchlists with file hash indicators.",
        ],
        "created": datetime.now(timezone.utc).isoformat(),
        "tlp": "TLP:GREEN",
    }


def _build_operational_brief(
    iocs: list[dict[str, Any]],
    scores: list[dict[str, Any]],
    relevance: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Campaign and TTP-focused brief for threat intel analysts and IR teams."""
    rel_map = {r["ioc_id"]: r for r in relevance}
    score_map = {s["ioc_id"]: s for s in scores}

    actors = Counter(ioc.get("actor", "") for ioc in iocs if ioc.get("actor"))
    campaigns = Counter(ioc.get("campaign", "") for ioc in iocs if ioc.get("campaign"))
    tactics = Counter(m.get("tactic", "") for m in mappings if m.get("tactic"))

    top_actors = [a for a, _ in actors.most_common(5)]
    top_campaigns = [c for c, _ in campaigns.most_common(5)]
    top_tactics = [t for t, _ in tactics.most_common(5)]

    high_rel = [i for i in iocs if rel_map.get(i.get("ioc_id", ""), {}).get("relevance", 0) >= 60]

    return {
        "brief_id": f"brief-ops-{uuid.uuid4().hex[:8]}",
        "level": "operational",
        "title": "Operational Intelligence Brief — Campaigns & TTPs",
        "executive_summary": (
            f"Tracking {len(actors)} threat actors across {len(campaigns)} campaigns. "
            f"{len(high_rel)} IOCs assessed as organisationally relevant."
        ),
        "technical_analysis": (
            f"Top actors: {', '.join(top_actors) or 'none identified'}. "
            f"Top campaigns: {', '.join(top_campaigns) or 'none identified'}. "
            f"Dominant tactics: {', '.join(top_tactics) or 'none identified'}."
        ),
        "ioc_appendix": [
            {"ioc_id": i.get("ioc_id"), "value": i.get("value"), "relevance": rel_map.get(i.get("ioc_id", ""), {}).get("relevance", 0)}
            for i in high_rel[:30]
        ],
        "attck_mapping": [{"tactic": t, "count": c} for t, c in tactics.most_common(10)],
        "recommendations": [
            f"Prioritize monitoring for {top_actors[0]} activity." if top_actors else "No actor attribution available.",
            "Update threat model with newly mapped TTPs.",
            "Brief incident response team on active campaign indicators.",
        ],
        "created": datetime.now(timezone.utc).isoformat(),
        "tlp": "TLP:AMBER",
    }


def _build_strategic_brief(
    iocs: list[dict[str, Any]],
    scores: list[dict[str, Any]],
    relevance: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Executive-level brief for CISO and security leadership."""
    actors = Counter(ioc.get("actor", "") for ioc in iocs if ioc.get("actor"))
    score_map = {s["ioc_id"]: s for s in scores}
    avg_conf = sum(s.get("confidence", 0) for s in scores) / max(len(scores), 1)
    rel_map = {r["ioc_id"]: r for r in relevance}
    avg_rel = sum(r.get("relevance", 0) for r in relevance) / max(len(relevance), 1)
    high_rel_count = sum(1 for r in relevance if r.get("relevance", 0) >= 60)

    tactics = Counter(m.get("tactic", "") for m in mappings if m.get("tactic"))
    technique_count = len({m["technique_id"] for m in mappings if m.get("technique_id")})

    return {
        "brief_id": f"brief-str-{uuid.uuid4().hex[:8]}",
        "level": "strategic",
        "title": "Strategic Threat Landscape Summary",
        "executive_summary": (
            f"Current intelligence cycle processed {len(iocs)} unique IOCs from "
            f"{len({s for i in iocs for s in i.get('sources', [])})} sources. "
            f"Average confidence: {avg_conf:.1f}%. "
            f"Organisational relevance: {high_rel_count} IOCs ({high_rel_count / max(len(iocs), 1) * 100:.0f}%) rated high-relevance."
        ),
        "technical_analysis": (
            f"Threat actor landscape: {len(actors)} tracked actors. "
            f"ATT&CK coverage: {technique_count} techniques across {len(tactics)} tactics."
        ),
        "ioc_appendix": [],
        "attck_mapping": [{"tactic": t, "count": c} for t, c in tactics.most_common(10)],
        "recommendations": [
            "Review threat model alignment with current actor targeting patterns.",
            "Ensure detection coverage across identified ATT&CK techniques.",
            "Schedule quarterly intelligence capability review.",
        ],
        "created": datetime.now(timezone.utc).isoformat(),
        "tlp": "TLP:AMBER",
    }


def generate_briefs(state: dict[str, Any]) -> dict[str, Any]:
    """Produce strategic, operational, and tactical intelligence briefs."""
    iocs = state.get("deduplicated_iocs", [])
    scores = state.get("confidence_scores", [])
    relevance = state.get("relevance_assessments", [])
    mappings = state.get("attck_mappings", [])

    briefs: list[dict[str, Any]] = []

    if iocs:
        briefs.append(_build_tactical_brief(iocs, scores, mappings))
        briefs.append(_build_operational_brief(iocs, scores, relevance, mappings))
        briefs.append(_build_strategic_brief(iocs, scores, relevance, mappings))

    logger.info("generate_briefs.done", count=len(briefs))
    return {"briefs": briefs}
