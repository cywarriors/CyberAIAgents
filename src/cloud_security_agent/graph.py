"""Graph definition for Cloud Security Posture Management Agent using LangGraph."""

from langgraph.graph import StateGraph
from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.nodes.discover import discover_resources
from cloud_security_agent.nodes.evaluate import evaluate_policies
from cloud_security_agent.nodes.scan_iac import scan_iac
from cloud_security_agent.nodes.prioritize import prioritize_findings
from cloud_security_agent.nodes.remediate import generate_remediation
from cloud_security_agent.nodes.drift import track_posture_drift
from cloud_security_agent.nodes.publish import publish_and_ticket


def create_cspm_graph():
    """Create the cloud security posture management processing graph.

    Flow:
        Start -> DiscoverResources
          -> [EvaluatePolicies, ScanIaC] (parallel fan-out)
          -> PrioritizeFindings -> GenerateRemediation
          -> TrackPostureDrift -> PublishAndTicket -> End
    """

    workflow = StateGraph(CloudPostureState)

    # Add nodes
    workflow.add_node("discover_resources", discover_resources)
    workflow.add_node("evaluate_policies", evaluate_policies)
    workflow.add_node("scan_iac", scan_iac)
    workflow.add_node("prioritize_findings", prioritize_findings)
    workflow.add_node("generate_remediation", generate_remediation)
    workflow.add_node("track_posture_drift", track_posture_drift)
    workflow.add_node("publish_and_ticket", publish_and_ticket)

    # Define edges following the SRS control flow
    # Start -> DiscoverResources
    workflow.set_entry_point("discover_resources")

    # DiscoverResources -> parallel fan-out to EvaluatePolicies and ScanIaC
    workflow.add_edge("discover_resources", "evaluate_policies")
    workflow.add_edge("discover_resources", "scan_iac")

    # Both parallel branches merge into PrioritizeFindings
    workflow.add_edge("evaluate_policies", "prioritize_findings")
    workflow.add_edge("scan_iac", "prioritize_findings")

    # Sequential: Prioritize -> Remediation -> Drift -> Publish
    workflow.add_edge("prioritize_findings", "generate_remediation")
    workflow.add_edge("generate_remediation", "track_posture_drift")
    workflow.add_edge("track_posture_drift", "publish_and_ticket")

    # Set exit
    workflow.set_finish_point("publish_and_ticket")

    return workflow.compile()


# Create graph instance
cspm_graph = create_cspm_graph()
