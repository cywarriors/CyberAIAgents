"""LangGraph pipeline for the Deception and Honeypot Agent."""
from __future__ import annotations
from functools import lru_cache
from langgraph.graph import END, START, StateGraph
from deception_honeypot_agent.models.state import DeceptionState
from deception_honeypot_agent.nodes.deploy_decoys import deploy_decoys
from deception_honeypot_agent.nodes.place_honey_creds import place_honey_creds
from deception_honeypot_agent.nodes.monitor_interactions import monitor_interactions
from deception_honeypot_agent.nodes.classify_interaction import classify_interaction
from deception_honeypot_agent.nodes.map_ttps import map_ttps
from deception_honeypot_agent.nodes.generate_alert import generate_alert
from deception_honeypot_agent.nodes.profile_attacker import profile_attacker
from deception_honeypot_agent.nodes.assess_coverage import assess_coverage
from deception_honeypot_agent.nodes.rotate_decoys import rotate_decoys


def build_deception_graph() -> StateGraph:
    """Build the deception pipeline.

    Flow::
        START → [deploy_decoys, place_honey_creds] (parallel)
          → monitor_interactions → classify_interaction → map_ttps
          → [generate_alert, profile_attacker] (parallel)
          → assess_coverage → rotate_decoys → END
    """
    g = StateGraph(DeceptionState)

    g.add_node("deploy_decoys", deploy_decoys)
    g.add_node("place_honey_creds", place_honey_creds)
    g.add_node("monitor_interactions", monitor_interactions)
    g.add_node("classify_interaction", classify_interaction)
    g.add_node("map_ttps", map_ttps)
    g.add_node("generate_alert", generate_alert)
    g.add_node("profile_attacker", profile_attacker)
    g.add_node("assess_coverage", assess_coverage)
    g.add_node("rotate_decoys", rotate_decoys)

    # Parallel start
    g.add_edge(START, "deploy_decoys")
    g.add_edge(START, "place_honey_creds")

    # Sequential processing
    g.add_edge("deploy_decoys", "monitor_interactions")
    g.add_edge("place_honey_creds", "monitor_interactions")
    g.add_edge("monitor_interactions", "classify_interaction")
    g.add_edge("classify_interaction", "map_ttps")

    # Parallel fan-out
    g.add_edge("map_ttps", "generate_alert")
    g.add_edge("map_ttps", "profile_attacker")

    # Converge
    g.add_edge("generate_alert", "assess_coverage")
    g.add_edge("profile_attacker", "assess_coverage")
    g.add_edge("assess_coverage", "rotate_decoys")
    g.add_edge("rotate_decoys", END)

    return g


@lru_cache()
def get_compiled_graph():
    return build_deception_graph().compile()
