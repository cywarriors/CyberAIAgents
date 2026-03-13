"""LangGraph phishing-verdict graph – control-flow orchestration."""

from langgraph.graph import END, StateGraph

from phishing_defense_agent.models.state import PhishingVerdictState
from phishing_defense_agent.nodes import (
    extract_email_features,
    validate_sender_auth,
    analyze_language_intent,
    detonate_urls_attachments,
    score_phishing_risk,
    apply_mail_action,
    notify_user_and_soc,
    learn_from_release,
)


def build_phishing_graph() -> StateGraph:
    """Construct phishing-verdict LangGraph.

    Flow:
        ExtractEmailFeatures
          -> ValidateSenderAuth
          -> AnalyzeLanguageIntent
          -> DetonateURLsAttachments
          -> ScorePhishingRisk
          -> ApplyMailAction
          -> NotifyUserAndSOC
          -> LearnFromRelease
          -> END
    """
    graph = StateGraph(PhishingVerdictState)

    # Register nodes
    graph.add_node("extract_email_features", extract_email_features)
    graph.add_node("validate_sender_auth", validate_sender_auth)
    graph.add_node("analyze_language_intent", analyze_language_intent)
    graph.add_node("detonate_urls_attachments", detonate_urls_attachments)
    graph.add_node("score_phishing_risk", score_phishing_risk)
    graph.add_node("apply_mail_action", apply_mail_action)
    graph.add_node("notify_user_and_soc", notify_user_and_soc)
    graph.add_node("learn_from_release", learn_from_release)

    # Edges (sequential pipeline)
    graph.set_entry_point("extract_email_features")
    graph.add_edge("extract_email_features", "validate_sender_auth")
    graph.add_edge("validate_sender_auth", "analyze_language_intent")
    graph.add_edge("analyze_language_intent", "detonate_urls_attachments")
    graph.add_edge("detonate_urls_attachments", "score_phishing_risk")
    graph.add_edge("score_phishing_risk", "apply_mail_action")
    graph.add_edge("apply_mail_action", "notify_user_and_soc")
    graph.add_edge("notify_user_and_soc", "learn_from_release")
    graph.add_edge("learn_from_release", END)

    return graph


def get_compiled_graph():
    """Return compiled runnable graph instance."""
    return build_phishing_graph().compile()
