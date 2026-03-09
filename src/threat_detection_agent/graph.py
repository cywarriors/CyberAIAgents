"""LangGraph detection graph – wires all nodes into the SRS-01 pipeline.

Control flow (from §12.3):
    Start -> IngestTelemetry -> NormalizeSchema
      -> [RuleMatch, BehaviorAnomaly]  (parallel)
      -> ScoreAndPrioritize -> Deduplicate -> PublishAlert -> FeedbackUpdate -> End
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from threat_detection_agent.models.state import EventBatchState
from threat_detection_agent.nodes.anomaly import behavior_anomaly
from threat_detection_agent.nodes.deduplicate import deduplicate
from threat_detection_agent.nodes.feedback import feedback_update
from threat_detection_agent.nodes.ingest import ingest_telemetry
from threat_detection_agent.nodes.normalize import normalize_schema
from threat_detection_agent.nodes.publish import publish_alert
from threat_detection_agent.nodes.rule_match import rule_match
from threat_detection_agent.nodes.score import score_and_prioritize


def build_detection_graph() -> StateGraph:
    """Construct and compile the threat-detection LangGraph."""

    graph = StateGraph(EventBatchState)

    # -- Register nodes -------------------------------------------------------
    graph.add_node("ingest_telemetry", ingest_telemetry)
    graph.add_node("normalize_schema", normalize_schema)
    graph.add_node("rule_match", rule_match)
    graph.add_node("behavior_anomaly", behavior_anomaly)
    graph.add_node("score_and_prioritize", score_and_prioritize)
    graph.add_node("deduplicate", deduplicate)
    graph.add_node("publish_alert", publish_alert)
    graph.add_node("feedback_update", feedback_update)

    # -- Edges ----------------------------------------------------------------
    graph.set_entry_point("ingest_telemetry")

    graph.add_edge("ingest_telemetry", "normalize_schema")

    # Fan-out: parallel detection branches
    graph.add_edge("normalize_schema", "rule_match")
    graph.add_edge("normalize_schema", "behavior_anomaly")

    # Fan-in: both branches converge at scoring
    graph.add_edge("rule_match", "score_and_prioritize")
    graph.add_edge("behavior_anomaly", "score_and_prioritize")

    # Linear tail
    graph.add_edge("score_and_prioritize", "deduplicate")
    graph.add_edge("deduplicate", "publish_alert")
    graph.add_edge("publish_alert", "feedback_update")
    graph.add_edge("feedback_update", END)

    return graph


def get_compiled_graph():
    """Return a compiled (runnable) graph instance."""
    return build_detection_graph().compile()
