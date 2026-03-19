from __future__ import annotations
import logging
from typing import Any
from fastapi import APIRouter, BackgroundTasks
from security_code_review_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

_EMPTY_STATE: dict[str, Any] = {
    "scan_target": {},
    "sast_findings": [],
    "secrets_findings": [],
    "sca_findings": [],
    "fix_suggestions": [],
    "policy_verdict": {},
    "sbom": {},
    "pr_comments": [],
    "lifecycle_updates": [],
    "processing_errors": [],
}


async def _run_scan(scan_target: dict) -> None:
    try:
        from security_code_review_agent.graph import get_compiled_graph
        state_in = {**_EMPTY_STATE, "scan_target": scan_target}
        result = get_compiled_graph().invoke(state_in)
        if hasattr(result, "model_dump"):
            result = result.model_dump()
        store = get_data_store()
        store.add_sast_findings(result.get("sast_findings", []))
        store.add_secrets_findings(result.get("secrets_findings", []))
        store.add_sca_findings(result.get("sca_findings", []))
        sbom = result.get("sbom", {})
        if sbom:
            store.add_sbom(sbom)
        verdict = result.get("policy_verdict", {})
        if verdict:
            store.add_policy_verdict(verdict)
    except Exception:
        logging.getLogger(__name__).exception("Scan error")


@router.post("")
async def trigger_scan(background_tasks: BackgroundTasks) -> dict[str, Any]:
    background_tasks.add_task(_run_scan, {})
    return {"status": "accepted", "message": "Code scan started"}


@router.get("")
async def list_scans() -> list[dict[str, Any]]:
    return get_data_store().get_scans()
