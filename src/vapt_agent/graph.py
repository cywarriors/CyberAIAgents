"""LangGraph VAPT pipeline – wires all 9 nodes into the SRS-13 pipeline.

Control flow (from §12.3):
    Start -> ValidateRoE -> DiscoverAssets -> ScanVulnerabilities
      -> ValidateExploits -> AnalyzeAttackPaths -> ScoreAndPrioritize
      -> GenerateRemediation -> GenerateReport -> PublishFindings -> End
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from vapt_agent.models.state import VAPTState
from vapt_agent.nodes.validate_roe import validate_roe
from vapt_agent.nodes.discover_assets import discover_assets
from vapt_agent.nodes.scan_vulnerabilities import scan_vulnerabilities
from vapt_agent.nodes.validate_exploits import validate_exploits
from vapt_agent.nodes.analyze_attack_paths import analyze_attack_paths
from vapt_agent.nodes.score_and_prioritize import score_and_prioritize
from vapt_agent.nodes.generate_remediation import generate_remediation
from vapt_agent.nodes.generate_report import generate_report
from vapt_agent.nodes.publish_findings import publish_findings


def build_vapt_graph() -> StateGraph:
    """Construct and compile the VAPT LangGraph pipeline."""

    graph = StateGraph(VAPTState)

    # -- Register nodes -------------------------------------------------------
    graph.add_node("validate_roe", validate_roe)
    graph.add_node("discover_assets", discover_assets)
    graph.add_node("scan_vulnerabilities", scan_vulnerabilities)
    graph.add_node("validate_exploits", validate_exploits)
    graph.add_node("analyze_attack_paths", analyze_attack_paths)
    graph.add_node("score_and_prioritize", score_and_prioritize)
    graph.add_node("generate_remediation", generate_remediation)
    graph.add_node("generate_report", generate_report)
    graph.add_node("publish_findings", publish_findings)

    # -- Edges (linear pipeline) -----------------------------------------------
    graph.set_entry_point("validate_roe")

    graph.add_edge("validate_roe", "discover_assets")
    graph.add_edge("discover_assets", "scan_vulnerabilities")
    graph.add_edge("scan_vulnerabilities", "validate_exploits")
    graph.add_edge("validate_exploits", "analyze_attack_paths")
    graph.add_edge("analyze_attack_paths", "score_and_prioritize")
    graph.add_edge("score_and_prioritize", "generate_remediation")
    graph.add_edge("generate_remediation", "generate_report")
    graph.add_edge("generate_report", "publish_findings")
    graph.add_edge("publish_findings", END)

    return graph


def get_compiled_graph():
    """Return a compiled (runnable) graph instance."""
    return build_vapt_graph().compile()
