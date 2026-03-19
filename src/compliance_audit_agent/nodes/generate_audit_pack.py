"""GenerateAuditPackNode – assemble evidence pack with SHA-256 integrity hashes (FR-05, SEC-01)."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import structlog

log = structlog.get_logger()


def _s(state: Any, key: str, default: Any) -> Any:
    if isinstance(state, dict):
        return state.get(key, default)
    return getattr(state, key, default)


def generate_audit_pack(state: Any) -> dict[str, Any]:
    """FR-05: Generate audit-ready evidence packs with cryptographic integrity."""
    evidence_items = _s(state, "evidence_items", [])
    framework_scores = _s(state, "framework_scores", {})
    gaps = _s(state, "gaps", [])
    packs: list[dict[str, Any]] = []

    by_framework: dict[str, list[dict[str, Any]]] = {}
    for ev in evidence_items:
        fw = ev.get("framework", "CUSTOM")
        by_framework.setdefault(fw, []).append(ev)

    for framework, items in by_framework.items():
        score_entry = framework_scores.get(framework, {})

        # Redact PII before hashing (SEC-03)
        clean_items = []
        for it in items:
            item_copy = dict(it)
            content = dict(item_copy.get("content", {}))
            # Remove common PII fields
            for pii_field in ("email", "username", "first_name", "last_name", "ssn", "dob"):
                content.pop(pii_field, None)
            item_copy["content"] = content
            item_copy["pii_redacted"] = True
            clean_items.append(item_copy)

        # Compute manifest hash (SEC-01)
        manifest_payload = json.dumps({
            "framework": framework,
            "evidence_items": clean_items,
            "framework_scores": score_entry,
            "gaps": [g for g in gaps if g.get("framework") == framework],
        }, sort_keys=True, default=str)
        manifest_hash = hashlib.sha256(manifest_payload.encode()).hexdigest()

        packs.append({
            "pack_id": str(uuid.uuid4()),
            "framework": framework,
            "org_unit": score_entry.get("org_unit", "enterprise"),
            "evidence_ids": [ev["evidence_id"] for ev in items],
            "evidence_count": len(items),
            "overall_score": score_entry.get("score", 0.0),
            "sha256_manifest": manifest_hash,
            "is_final": False,  # Awaits Compliance Manager approval
            "generated_at": __import__("datetime").datetime.utcnow().isoformat(),
            "version": 1,
        })

    log.info("generate_audit_pack.done", packs=len(packs))
    return {"audit_packs": packs}
