"""Dashboard endpoints."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter
from compliance_audit_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/compliance")
async def dashboard_compliance() -> dict[str, Any]:
    store = get_data_store()
    framework_scores = store.get_framework_scores()
    gaps = store.get_gaps()
    packs = store.get_audit_packs()
    return {
        "framework_scores": framework_scores,
        "total_gaps": len(gaps),
        "critical_gaps": sum(1 for g in gaps if g.get("severity") == "critical"),
        "high_gaps": sum(1 for g in gaps if g.get("severity") == "high"),
        "audit_packs_generated": len(packs),
        "overall_compliance": (
            sum(v.get("score", 0) for v in framework_scores.values()) / len(framework_scores)
            if framework_scores else 0.0
        ),
    }
