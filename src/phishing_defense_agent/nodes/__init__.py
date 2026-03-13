"""Pipeline nodes for Phishing Defense Agent."""

from phishing_defense_agent.nodes.extract import extract_email_features
from phishing_defense_agent.nodes.auth import validate_sender_auth
from phishing_defense_agent.nodes.language import analyze_language_intent
from phishing_defense_agent.nodes.detonate import detonate_urls_attachments
from phishing_defense_agent.nodes.score import score_phishing_risk
from phishing_defense_agent.nodes.action import apply_mail_action
from phishing_defense_agent.nodes.notify import notify_user_and_soc
from phishing_defense_agent.nodes.feedback import learn_from_release

__all__ = [
    "extract_email_features",
    "validate_sender_auth",
    "analyze_language_intent",
    "detonate_urls_attachments",
    "score_phishing_risk",
    "apply_mail_action",
    "notify_user_and_soc",
    "learn_from_release",
]
