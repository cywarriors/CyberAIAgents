"""AnalyzeLanguageIntentNode – NLP classification of social-engineering intent (FR-03)."""

from __future__ import annotations

import re
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ── Pattern libraries ──────────────────────────────────────────

_URGENCY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"immediate\s+action\s+required",
        r"act\s+now",
        r"urgent",
        r"expires?\s+(today|soon|in\s+\d+\s+hours?)",
        r"last\s+chance",
        r"final\s+notice",
        r"your\s+account\s+(will\s+be|has\s+been)\s+(suspended|locked|closed|deactivated)",
        r"verify\s+(your|the)\s+(account|identity|information)\s+(immediately|now|within)",
        r"failure\s+to\s+(respond|act|verify)",
        r"limited\s+time",
        r"within\s+24\s+hours?\b",
    ]
]

_CREDENTIAL_HARVEST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(click|follow)\s+(here|this\s+link|below)\s+to\s+(verify|confirm|update|sign\s+in|log\s*in)",
        r"enter\s+(your|the)\s+(password|credentials|login)",
        r"confirm\s+(your|the)\s+(identity|account|details)",
        r"(reset|change|update)\s+(your|the)\s+password",
        r"sign\s+in\s+to\s+(verify|confirm|review)",
        r"security\s+(alert|notification|warning).*sign\s+in",
    ]
]

_FINANCIAL_FRAUD_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"wire\s+transfer",
        r"bank\s+account\s+(details|information|number)",
        r"invoice\s+(attached|enclosed|#?\d+)",
        r"payment\s+(overdue|due|required|pending)",
        r"purchase\s+order",
        r"change\s+(of\s+)?(bank|payment|account)\s+(details|information)",
        r"updated?\s+banking\s+(details|information)",
    ]
]

_BEC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(CEO|CFO|CTO|president|director)\b.*\b(request|asking|need)",
        r"confidential\s+(request|matter|transaction)",
        r"do\s+not\s+(share|discuss|forward|tell)",
        r"are\s+you\s+available\?",
        r"can\s+you\s+handle\s+(this|a)\s+(task|request|transfer)",
        r"i\s+need\s+(you|your\s+help)\s+with\s+(a|an)\s+(urgent|confidential)",
        r"gift\s+cards?\b",
    ]
]

_IMPERSONATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(helpdesk|IT\s+department|support\s+team|admin|administrator)\b",
        r"(microsoft|google|apple|amazon|paypal)\s+(support|team|security)",
        r"your\s+(IT|tech)\s+(team|department|support)",
    ]
]

_MALWARE_DELIVERY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(enable|allow)\s+(macros|content|editing)",
        r"(open|download|view)\s+the\s+attached",
        r"password\s+(for|to\s+open)\s+(the\s+)?(file|document|attachment)\s+is",
    ]
]

_ALL_PATTERN_SETS: list[tuple[str, list[re.Pattern[str]]]] = [
    ("urgency", _URGENCY_PATTERNS),
    ("credential_harvest", _CREDENTIAL_HARVEST_PATTERNS),
    ("financial_fraud", _FINANCIAL_FRAUD_PATTERNS),
    ("business_email_compromise", _BEC_PATTERNS),
    ("impersonation", _IMPERSONATION_PATTERNS),
    ("malware_delivery", _MALWARE_DELIVERY_PATTERNS),
]


def _analyze_text(text: str) -> list[dict[str, Any]]:
    """Run all pattern sets against text and return detected signals."""
    if not text:
        return []

    signals: list[dict[str, Any]] = []
    for signal_type, patterns in _ALL_PATTERN_SETS:
        matched: list[str] = []
        for pat in patterns:
            m = pat.search(text)
            if m:
                matched.append(m.group(0))

        if matched:
            # Confidence based on number of matching patterns
            confidence = min(0.95, 0.40 + 0.15 * len(matched))
            signals.append({
                "signal_type": signal_type,
                "confidence": round(confidence, 2),
                "evidence": matched[0][:200],
                "matched_patterns": matched[:5],
                "match_count": len(matched),
            })

    return signals


def _detect_display_name_spoofing(
    sender_display_name: str, sender_address: str
) -> dict[str, Any] | None:
    """Detect VIP impersonation via display-name spoofing (FR-11)."""
    if not sender_display_name:
        return None

    name_lower = sender_display_name.lower()
    addr_lower = sender_address.lower()

    # Check if display name contains an email address different from sender
    email_in_name = re.search(r"[\w.+-]+@[\w.-]+\.\w+", sender_display_name)
    if email_in_name and email_in_name.group(0).lower() != addr_lower:
        return {
            "signal_type": "impersonation",
            "confidence": 0.85,
            "evidence": f"Display name contains different email: {email_in_name.group(0)}",
            "matched_patterns": ["display_name_email_mismatch"],
            "match_count": 1,
        }

    return None


def analyze_language_intent(state: dict[str, Any]) -> dict[str, Any]:
    """Classify suspicious language patterns and social-engineering intent.

    Implements FR-03 and FR-11 (VIP impersonation / display-name spoofing).
    """
    features_list: list[dict] = state.get("email_features", [])

    logger.info("analyze_language_intent", email_count=len(features_list))

    all_signals: list[dict[str, Any]] = []
    for feat in features_list:
        message_id = feat.get("message_id", "")
        body = feat.get("body_text", "")
        subject = feat.get("subject", "")
        combined_text = f"{subject} {body}"

        signals = _analyze_text(combined_text)

        # Display-name spoofing check
        spoof = _detect_display_name_spoofing(
            feat.get("sender_display_name", ""),
            feat.get("sender_address", ""),
        )
        if spoof:
            signals.append(spoof)

        for sig in signals:
            sig["message_id"] = message_id

        all_signals.extend(signals)

    logger.info("language_analysis_complete", signals_detected=len(all_signals))
    return {"content_signals": all_signals}
