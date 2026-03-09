"""ScoreAndPrioritizeNode – merge rule + anomaly results, assign severity/confidence."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
_RANK_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


def _anomaly_severity(score: float) -> str:
    if score >= 0.9:
        return "Critical"
    if score >= 0.7:
        return "High"
    if score >= 0.4:
        return "Medium"
    if score >= 0.2:
        return "Low"
    return "Info"


def score_and_prioritize(state: dict[str, Any]) -> dict[str, Any]:
    """Merge rule matches and anomaly results into scored alert candidates."""
    matched_rules: list[dict] = state.get("matched_rules", [])
    anomalies: list[dict] = state.get("anomalies", [])
    candidates: list[dict] = []

    # Convert rule matches to candidates
    for rm in matched_rules:
        confidence = 85  # rule matches start with high confidence
        candidates.append(
            {
                "candidate_id": f"cand-{uuid.uuid4().hex[:12]}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": rm.get("severity", "Medium"),
                "confidence": confidence,
                "mitre_technique_ids": [rm.get("mitre_technique_id", "")],
                "mitre_tactics": [rm.get("mitre_tactic", "")],
                "source_type": "rule",
                "entity_ids": [],
                "matched_event_ids": rm.get("matched_event_ids", []),
                "evidence": rm.get("raw_evidence", []),
                "description": rm.get("description", ""),
            }
        )

    # Convert anomaly results to candidates
    for anom in anomalies:
        score = float(anom.get("anomaly_score", 0))
        severity = _anomaly_severity(score)
        confidence = int(score * 100)
        candidates.append(
            {
                "candidate_id": f"cand-{uuid.uuid4().hex[:12]}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": severity,
                "confidence": confidence,
                "mitre_technique_ids": [],
                "mitre_tactics": [],
                "source_type": "anomaly",
                "entity_ids": [anom.get("entity_id", "")],
                "matched_event_ids": anom.get("matched_event_ids", []),
                "evidence": [anom],
                "description": anom.get("description", ""),
            }
        )

    # Merge overlapping candidates (same event IDs hit by both rule and anomaly)
    merged = _merge_overlapping(candidates)

    logger.info("score_and_prioritize", candidate_count=len(merged))
    return {"alert_candidates": merged}


def _merge_overlapping(candidates: list[dict]) -> list[dict]:
    """If a rule candidate and anomaly candidate share event IDs, merge them."""
    event_map: dict[str, list[dict]] = {}
    for c in candidates:
        for eid in c.get("matched_event_ids", []):
            event_map.setdefault(eid, []).append(c)

    merged_ids: set[str] = set()
    result: list[dict] = []

    for c in candidates:
        cid = c["candidate_id"]
        if cid in merged_ids:
            continue

        # Find partners
        partners = []
        for eid in c.get("matched_event_ids", []):
            for partner in event_map.get(eid, []):
                pid = partner["candidate_id"]
                if pid != cid and pid not in merged_ids:
                    partners.append(partner)
                    merged_ids.add(pid)

        if partners:
            # Merge: take highest severity, average confidence, union fields
            all_items = [c] + partners
            max_sev = max(
                all_items,
                key=lambda x: _SEVERITY_RANK.get(x.get("severity", "Info"), 0),
            )
            avg_conf = int(
                sum(x.get("confidence", 50) for x in all_items) / len(all_items)
            )
            merged = {
                "candidate_id": cid,
                "timestamp": c["timestamp"],
                "severity": max_sev["severity"],
                "confidence": min(avg_conf + 10, 100),  # boost for corroboration
                "mitre_technique_ids": list(
                    {t for x in all_items for t in x.get("mitre_technique_ids", [])}
                ),
                "mitre_tactics": list(
                    {t for x in all_items for t in x.get("mitre_tactics", [])}
                ),
                "source_type": "hybrid",
                "entity_ids": list(
                    {e for x in all_items for e in x.get("entity_ids", [])}
                ),
                "matched_event_ids": list(
                    {e for x in all_items for e in x.get("matched_event_ids", [])}
                ),
                "evidence": [e for x in all_items for e in x.get("evidence", [])],
                "description": " | ".join(
                    x.get("description", "") for x in all_items if x.get("description")
                ),
            }
            result.append(merged)
        else:
            result.append(c)

        merged_ids.add(cid)

    return result
