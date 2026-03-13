"""LangGraph pipeline for the Identity & Access Monitoring Agent (SRS-06 §12)."""

from __future__ import annotations

from functools import lru_cache

from langgraph.graph import StateGraph

from identity_access_agent.models.state import IdentityRiskState
from identity_access_agent.nodes.ingest import ingest_identity_events
from identity_access_agent.nodes.session import analyze_session_patterns
from identity_access_agent.nodes.privilege import detect_privilege_changes
from identity_access_agent.nodes.takeover import detect_takeover_signals
from identity_access_agent.nodes.risk import compute_identity_risk
from identity_access_agent.nodes.recommend import recommend_controls
from identity_access_agent.nodes.alert import open_case_or_ticket
from identity_access_agent.nodes.feedback import feedback_and_policy_tune


def build_identity_graph() -> StateGraph:
    """Construct the 8-node identity risk analysis graph.

    Control flow (§12.3):
        Start → IngestIdentityEvents
          → SessionPattern → PrivilegeChange → DetectTakeoverSignals
          → ComputeIdentityRisk → RecommendControl
          → OpenCaseOrTicket → FeedbackAndPolicyTune → End
    """
    graph = StateGraph(IdentityRiskState)

    graph.add_node("ingest_identity_events", ingest_identity_events)
    graph.add_node("analyze_session_patterns", analyze_session_patterns)
    graph.add_node("detect_privilege_changes", detect_privilege_changes)
    graph.add_node("detect_takeover_signals", detect_takeover_signals)
    graph.add_node("compute_identity_risk", compute_identity_risk)
    graph.add_node("recommend_controls", recommend_controls)
    graph.add_node("open_case_or_ticket", open_case_or_ticket)
    graph.add_node("feedback_and_policy_tune", feedback_and_policy_tune)

    graph.set_entry_point("ingest_identity_events")
    graph.add_edge("ingest_identity_events", "analyze_session_patterns")
    graph.add_edge("analyze_session_patterns", "detect_privilege_changes")
    graph.add_edge("detect_privilege_changes", "detect_takeover_signals")
    graph.add_edge("detect_takeover_signals", "compute_identity_risk")
    graph.add_edge("compute_identity_risk", "recommend_controls")
    graph.add_edge("recommend_controls", "open_case_or_ticket")
    graph.add_edge("open_case_or_ticket", "feedback_and_policy_tune")
    graph.set_finish_point("feedback_and_policy_tune")

    return graph


@lru_cache(maxsize=1)
def get_compiled_graph():
    """Return compiled, reusable graph instance."""
    return build_identity_graph().compile()
