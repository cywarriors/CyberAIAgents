"""LangGraph definition for the Compliance and Audit Agent pipeline."""

from __future__ import annotations

from functools import lru_cache

from langgraph.graph import END, START, StateGraph

from compliance_audit_agent.models.state import ComplianceState
from compliance_audit_agent.nodes.collect_evidence import collect_evidence
from compliance_audit_agent.nodes.map_controls import map_controls
from compliance_audit_agent.nodes.assess_effectiveness import assess_effectiveness
from compliance_audit_agent.nodes.identify_gaps import identify_gaps
from compliance_audit_agent.nodes.score_compliance import score_compliance
from compliance_audit_agent.nodes.generate_audit_pack import generate_audit_pack
from compliance_audit_agent.nodes.track_drift import track_drift
from compliance_audit_agent.nodes.create_remediation_tickets import create_remediation_tickets


def build_compliance_graph() -> StateGraph:
    """Construct the Compliance and Audit processing graph.

    Flow::

        START → collect_evidence → map_controls → assess_effectiveness
          → identify_gaps → score_compliance
          → fan-out [generate_audit_pack, track_drift, create_remediation_tickets]
          → END
    """
    g = StateGraph(ComplianceState)

    g.add_node("collect_evidence", collect_evidence)
    g.add_node("map_controls", map_controls)
    g.add_node("assess_effectiveness", assess_effectiveness)
    g.add_node("identify_gaps", identify_gaps)
    g.add_node("score_compliance", score_compliance)
    g.add_node("generate_audit_pack", generate_audit_pack)
    g.add_node("track_drift", track_drift)
    g.add_node("create_remediation_tickets", create_remediation_tickets)

    g.add_edge(START, "collect_evidence")
    g.add_edge("collect_evidence", "map_controls")
    g.add_edge("map_controls", "assess_effectiveness")
    g.add_edge("assess_effectiveness", "identify_gaps")
    g.add_edge("identify_gaps", "score_compliance")

    # Parallel fan-out
    g.add_edge("score_compliance", "generate_audit_pack")
    g.add_edge("score_compliance", "track_drift")
    g.add_edge("score_compliance", "create_remediation_tickets")

    g.add_edge("generate_audit_pack", END)
    g.add_edge("track_drift", END)
    g.add_edge("create_remediation_tickets", END)

    return g


@lru_cache()
def get_compiled_graph():
    """Return a compiled (and cached) runnable graph."""
    return build_compliance_graph().compile()
