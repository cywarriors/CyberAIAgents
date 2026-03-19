"""Pipeline trigger route."""
from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends

from ..dependencies import get_store
from ..store import InMemoryStore
from ...graph import get_compiled_graph

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["pipeline"])


def _run_pipeline(store: InMemoryStore, payload: dict) -> None:
    try:
        graph = get_compiled_graph()
        result = graph.invoke(payload)
        if isinstance(result, dict):
            store.add_decoys(result.get("decoy_inventory") or [])
            store.add_interactions(result.get("classified_interactions") or [])
            store.add_alerts(result.get("alerts") or [])
            for p in result.get("attacker_profiles") or []:
                store.add_profile(p)
            if result.get("coverage_assessment"):
                store.set_coverage(result["coverage_assessment"])
    except Exception:  # noqa: BLE001
        logger.exception("Deception pipeline error")


@router.post("/process", status_code=202)
def trigger_pipeline(
    payload: dict,
    background_tasks: BackgroundTasks,
    store: InMemoryStore = Depends(get_store),
) -> dict:
    background_tasks.add_task(_run_pipeline, store, payload)
    return {"status": "accepted"}
