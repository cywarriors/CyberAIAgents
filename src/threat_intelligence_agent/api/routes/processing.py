"""Processing endpoint — invoke the LangGraph pipeline via API."""

from __future__ import annotations

from fastapi import APIRouter

from threat_intelligence_agent.api.dependencies import get_store
from threat_intelligence_agent.api.schemas import ProcessIntelRequest

router = APIRouter(prefix="/api/v1", tags=["processing"])


@router.post("/process")
async def process_intel(body: ProcessIntelRequest):
    """Run the threat-intel pipeline on supplied records.

    Results are stored in the in-memory store for the GUI to consume.
    """
    from threat_intelligence_agent.nodes.ingest_feeds import ingest_feeds
    from threat_intelligence_agent.nodes.normalize_stix import normalize_to_stix
    from threat_intelligence_agent.nodes.deduplicate import deduplicate_iocs
    from threat_intelligence_agent.nodes.score_confidence import score_confidence
    from threat_intelligence_agent.nodes.assess_relevance import assess_relevance
    from threat_intelligence_agent.nodes.map_attck import map_attck
    from threat_intelligence_agent.nodes.generate_briefs import generate_briefs
    from threat_intelligence_agent.nodes.distribute_iocs import distribute_iocs
    from threat_intelligence_agent.nodes.feedback_loop import feedback_loop

    state: dict = {"raw_intel": body.intel_records}
    state.update(ingest_feeds(state))
    state.update(normalize_to_stix(state))
    state.update(deduplicate_iocs(state))
    state.update(score_confidence(state))
    state.update(assess_relevance(state))
    state.update(map_attck(state))
    state.update(generate_briefs(state))
    state.update(distribute_iocs(state))
    state.update(feedback_loop(state))

    # Persist results into the in-memory store for GUI
    store = get_store()
    score_map = {s["ioc_id"]: s.get("confidence", 0) for s in state.get("confidence_scores", [])}
    rel_map = {r["ioc_id"]: r.get("relevance", 0) for r in state.get("relevance_assessments", [])}

    for ioc in state.get("deduplicated_iocs", []):
        ioc["confidence"] = score_map.get(ioc.get("ioc_id", ""), 0)
        ioc["relevance"] = rel_map.get(ioc.get("ioc_id", ""), 0)
        store.iocs.append(ioc)

    for brief in state.get("briefs", []):
        store.briefs.append(brief)

    return {
        "status": "ok",
        "iocs_processed": len(state.get("deduplicated_iocs", [])),
        "briefs_generated": len(state.get("briefs", [])),
        "distribution_results": state.get("distribution_results", []),
    }
