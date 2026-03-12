"""LangGraph triage graph – wires all nodes into the SRS-02 pipeline.

Control flow (from §12.3):
    Start -> IngestAlert -> CorrelateIncident -> EnrichEntity
      -> RiskScore -> GenerateSummary -> RecommendActions
      -> CreateOrUpdateCase -> FeedbackLearn -> End
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from incident_triage_agent.models.state import TriageState
from incident_triage_agent.nodes.case_manager import create_or_update_case
from incident_triage_agent.nodes.correlate import correlate_incident
from incident_triage_agent.nodes.enrich import enrich_entity
from incident_triage_agent.nodes.feedback import feedback_learn
from incident_triage_agent.nodes.ingest import ingest_alert
from incident_triage_agent.nodes.recommend import recommend_actions
from incident_triage_agent.nodes.risk_score import risk_score
from incident_triage_agent.nodes.summarize import generate_summary


def build_triage_graph() -> StateGraph:
    """Construct and compile the incident-triage LangGraph."""

    graph = StateGraph(TriageState)

    # -- Register nodes (§12.2) -----------------------------------------------
    graph.add_node("ingest_alert", ingest_alert)
    graph.add_node("correlate_incident", correlate_incident)
    graph.add_node("enrich_entity", enrich_entity)
    graph.add_node("risk_score", risk_score)
    graph.add_node("generate_summary", generate_summary)
    graph.add_node("recommend_actions", recommend_actions)
    graph.add_node("create_or_update_case", create_or_update_case)
    graph.add_node("feedback_learn", feedback_learn)

    # -- Edges (§12.3) --------------------------------------------------------
    graph.set_entry_point("ingest_alert")

    graph.add_edge("ingest_alert", "correlate_incident")
    graph.add_edge("correlate_incident", "enrich_entity")
    graph.add_edge("enrich_entity", "risk_score")
    graph.add_edge("risk_score", "generate_summary")
    graph.add_edge("generate_summary", "recommend_actions")
    graph.add_edge("recommend_actions", "create_or_update_case")
    graph.add_edge("create_or_update_case", "feedback_learn")
    graph.add_edge("feedback_learn", END)

    return graph


def get_compiled_graph():
    """Return a compiled (runnable) graph instance."""
    return build_triage_graph().compile()
