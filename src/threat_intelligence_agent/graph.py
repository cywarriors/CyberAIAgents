"""LangGraph definition for the Threat Intelligence Agent pipeline."""

from __future__ import annotations

from functools import lru_cache

from langgraph.graph import END, START, StateGraph

from threat_intelligence_agent.models.state import ThreatIntelState
from threat_intelligence_agent.nodes.ingest_feeds import ingest_feeds
from threat_intelligence_agent.nodes.normalize_stix import normalize_to_stix
from threat_intelligence_agent.nodes.deduplicate import deduplicate_iocs
from threat_intelligence_agent.nodes.score_confidence import score_confidence
from threat_intelligence_agent.nodes.assess_relevance import assess_relevance
from threat_intelligence_agent.nodes.map_attck import map_attck
from threat_intelligence_agent.nodes.generate_briefs import generate_briefs
from threat_intelligence_agent.nodes.distribute_iocs import distribute_iocs
from threat_intelligence_agent.nodes.feedback_loop import feedback_loop


def build_threat_intel_graph() -> StateGraph:
    """Construct the Threat Intelligence processing graph.

    Flow::

        START → ingest_feeds → normalize_to_stix → deduplicate_iocs
          → score_confidence → assess_relevance → map_attck
          → fan-out [generate_briefs, distribute_iocs]
          → fan-in → feedback_loop → END
    """
    g = StateGraph(ThreatIntelState)

    # ── Nodes ────────────────────────────────────────────────────────────
    g.add_node("ingest_feeds", ingest_feeds)
    g.add_node("normalize_to_stix", normalize_to_stix)
    g.add_node("deduplicate_iocs", deduplicate_iocs)
    g.add_node("score_confidence", score_confidence)
    g.add_node("assess_relevance", assess_relevance)
    g.add_node("map_attck", map_attck)
    g.add_node("generate_briefs", generate_briefs)
    g.add_node("distribute_iocs", distribute_iocs)
    g.add_node("feedback_loop", feedback_loop)

    # ── Linear edges ─────────────────────────────────────────────────────
    g.add_edge(START, "ingest_feeds")
    g.add_edge("ingest_feeds", "normalize_to_stix")
    g.add_edge("normalize_to_stix", "deduplicate_iocs")
    g.add_edge("deduplicate_iocs", "score_confidence")
    g.add_edge("score_confidence", "assess_relevance")
    g.add_edge("assess_relevance", "map_attck")

    # ── Parallel fan-out: generate_briefs + distribute_iocs ──────────────
    g.add_edge("map_attck", "generate_briefs")
    g.add_edge("map_attck", "distribute_iocs")

    # ── Fan-in to feedback_loop ──────────────────────────────────────────
    g.add_edge("generate_briefs", "feedback_loop")
    g.add_edge("distribute_iocs", "feedback_loop")

    g.add_edge("feedback_loop", END)

    return g


@lru_cache()
def get_compiled_graph():
    """Return a compiled (and cached) runnable graph."""
    return build_threat_intel_graph().compile()
