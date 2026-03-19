"""Processing trigger endpoint."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, BackgroundTasks
from compliance_audit_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1", tags=["processing"])

_EMPTY_STATE: dict[str, Any] = {
    "evidence_items": [],
    "control_mappings": [],
    "effectiveness_scores": {},
    "gaps": [],
    "framework_scores": {},
    "audit_packs": [],
    "drift_alerts": [],
    "remediation_tickets": [],
    "processing_errors": [],
}


async def _run_pipeline(seed_evidence: list[dict[str, Any]]) -> None:
    import logging
    try:
        from compliance_audit_agent.graph import get_compiled_graph
        state_in = {**_EMPTY_STATE, "evidence_items": seed_evidence}
        compiled = get_compiled_graph()
        result = compiled.invoke(state_in)
        # Result may be a Pydantic model or dict
        if hasattr(result, "model_dump"):
            result = result.model_dump()
        store = get_data_store()
        store.add_evidence(result.get("evidence_items", []))
        store.add_audit_packs(result.get("audit_packs", []))
        store.add_gaps(result.get("gaps", []))
        store.set_framework_scores(result.get("framework_scores", {}))
    except Exception:  # noqa: BLE001
        logging.getLogger(__name__).exception("Pipeline execution error")


@router.post("/process")
async def trigger_pipeline(background_tasks: BackgroundTasks) -> dict[str, Any]:
    background_tasks.add_task(_run_pipeline, [])
    return {"status": "accepted", "message": "Compliance assessment pipeline started"}
