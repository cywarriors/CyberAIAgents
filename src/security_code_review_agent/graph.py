from __future__ import annotations
from functools import lru_cache
from langgraph.graph import END, START, StateGraph
from security_code_review_agent.models.state import CodeReviewState
from security_code_review_agent.nodes.ingest_code import ingest_code
from security_code_review_agent.nodes.sast_scan import sast_scan
from security_code_review_agent.nodes.detect_secrets import detect_secrets
from security_code_review_agent.nodes.sca_scan import sca_scan
from security_code_review_agent.nodes.generate_fixes import generate_fixes
from security_code_review_agent.nodes.evaluate_policy import evaluate_policy
from security_code_review_agent.nodes.post_pr_comments import post_pr_comments
from security_code_review_agent.nodes.generate_sbom import generate_sbom
from security_code_review_agent.nodes.track_lifecycle import track_lifecycle


def build_code_review_graph() -> StateGraph:
    g = StateGraph(CodeReviewState)
    g.add_node("ingest_code", ingest_code)
    g.add_node("sast_scan", sast_scan)
    g.add_node("detect_secrets", detect_secrets)
    g.add_node("sca_scan", sca_scan)
    g.add_node("generate_fixes", generate_fixes)
    g.add_node("evaluate_policy", evaluate_policy)
    g.add_node("post_pr_comments", post_pr_comments)
    g.add_node("generate_sbom", generate_sbom)
    g.add_node("track_lifecycle", track_lifecycle)

    g.add_edge(START, "ingest_code")
    g.add_edge("ingest_code", "sast_scan")
    g.add_edge("ingest_code", "detect_secrets")
    g.add_edge("ingest_code", "sca_scan")
    g.add_edge("sast_scan", "generate_fixes")
    g.add_edge("detect_secrets", "generate_fixes")
    g.add_edge("sca_scan", "generate_fixes")
    g.add_edge("generate_fixes", "evaluate_policy")
    g.add_edge("evaluate_policy", "post_pr_comments")
    g.add_edge("evaluate_policy", "generate_sbom")
    g.add_edge("post_pr_comments", "track_lifecycle")
    g.add_edge("generate_sbom", "track_lifecycle")
    g.add_edge("track_lifecycle", END)
    return g


@lru_cache()
def get_compiled_graph():
    return build_code_review_graph().compile()
