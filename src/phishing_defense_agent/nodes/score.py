"""ScorePhishingRiskNode – combine signals into final risk score (FR-05)."""

from __future__ import annotations

from typing import Any

import structlog

from phishing_defense_agent.config import get_settings

logger = structlog.get_logger(__name__)


def _auth_risk_score(auth: dict[str, Any]) -> float:
    """Convert authentication result into a 0-100 risk score (100 = highest risk)."""
    reputation = auth.get("sender_reputation_score", 50.0)
    # Invert: low reputation = high risk
    return max(0.0, min(100.0, 100.0 - reputation))


def _content_risk_score(signals: list[dict[str, Any]]) -> float:
    """Aggregate content signals into a single risk score."""
    if not signals:
        return 0.0
    max_confidence = max(s.get("confidence", 0.0) for s in signals)
    signal_count_bonus = min(30.0, len(signals) * 10.0)
    return min(100.0, max_confidence * 70.0 + signal_count_bonus)


def _url_risk_score(sandbox: dict[str, Any]) -> float:
    """Score URL risk from sandbox results."""
    url_results = sandbox.get("url_results", [])
    if not url_results:
        return 0.0

    scores: list[float] = []
    for r in url_results:
        verdict = r.get("sandbox_verdict", "clean")
        if verdict == "malicious":
            scores.append(100.0)
        elif verdict == "suspicious":
            scores.append(65.0)
        elif r.get("is_known_phishing"):
            scores.append(95.0)
        elif r.get("is_shortened"):
            scores.append(25.0)
        else:
            scores.append(0.0)

    return max(scores) if scores else 0.0


def _attachment_risk_score(sandbox: dict[str, Any]) -> float:
    """Score attachment risk from sandbox results."""
    att_results = sandbox.get("attachment_results", [])
    if not att_results:
        return 0.0

    scores: list[float] = []
    for r in att_results:
        verdict = r.get("sandbox_verdict", "clean")
        if verdict == "malicious":
            scores.append(100.0)
        elif verdict == "suspicious":
            scores.append(60.0)
        else:
            scores.append(0.0)

    return max(scores) if scores else 0.0


def _threat_intel_score(auth: dict[str, Any], sandbox: dict[str, Any]) -> float:
    """Score based on threat intelligence matches."""
    score = 0.0
    if auth.get("is_lookalike_domain"):
        score += 40.0
    if auth.get("domain_age_days", 365) < 30:
        score += 20.0

    # Count known-phishing URLs
    phishing_urls = sum(
        1 for r in sandbox.get("url_results", []) if r.get("is_known_phishing")
    )
    if phishing_urls:
        score += min(40.0, phishing_urls * 20.0)

    return min(100.0, score)


def _determine_verdict(risk_score: float, settings: Any) -> tuple[str, str]:
    """Map risk score to verdict and action."""
    if risk_score >= settings.risk_threshold_block:
        return "malicious", "block"
    if risk_score >= settings.risk_threshold_quarantine:
        return "malicious", "quarantine"
    if risk_score >= settings.risk_threshold_warn:
        return "suspicious", "warn"
    return "clean", "allow"


def score_phishing_risk(state: dict[str, Any]) -> dict[str, Any]:
    """Combine all signals into a weighted risk score and assign verdict.

    Implements FR-05.
    """
    settings = get_settings()
    features_list: list[dict] = state.get("email_features", [])
    auth_results: list[dict] = state.get("auth_results", [])
    content_signals: list[dict] = state.get("content_signals", [])
    sandbox_results: list[dict] = state.get("sandbox_results", [])

    logger.info("score_phishing_risk", email_count=len(features_list))

    # Index by message_id
    auth_by_id = {a["message_id"]: a for a in auth_results}
    sandbox_by_id = {s["message_id"]: s for s in sandbox_results}

    # Group content signals by message_id
    signals_by_id: dict[str, list[dict]] = {}
    for sig in content_signals:
        mid = sig.get("message_id", "")
        signals_by_id.setdefault(mid, []).append(sig)

    risk_scores: list[dict[str, Any]] = []
    for feat in features_list:
        message_id = feat.get("message_id", "")
        auth = auth_by_id.get(message_id, {})
        sandbox = sandbox_by_id.get(message_id, {})
        signals = signals_by_id.get(message_id, [])

        # Component scores
        auth_score = _auth_risk_score(auth)
        content_score = _content_risk_score(signals)
        url_score = _url_risk_score(sandbox)
        att_score = _attachment_risk_score(sandbox)
        ti_score = _threat_intel_score(auth, sandbox)

        # Weighted composite
        composite = (
            auth_score * settings.weight_sender_auth
            + content_score * settings.weight_content_analysis
            + url_score * settings.weight_url_reputation
            + att_score * settings.weight_attachment_risk
            + ti_score * settings.weight_threat_intel
        )
        composite = min(100.0, round(composite, 2))

        verdict, action = _determine_verdict(composite, settings)

        # Confidence based on signal density
        signal_count = len(signals) + len(sandbox.get("url_results", [])) + len(
            sandbox.get("attachment_results", [])
        )
        confidence = min(0.99, 0.5 + 0.05 * signal_count)

        risk_scores.append({
            "message_id": message_id,
            "risk_score": composite,
            "verdict": verdict,
            "action": action,
            "confidence": round(confidence, 2),
            "components": {
                "sender_auth": round(auth_score, 2),
                "content_analysis": round(content_score, 2),
                "url_reputation": round(url_score, 2),
                "attachment_risk": round(att_score, 2),
                "threat_intel": round(ti_score, 2),
            },
            "explanation": _build_explanation(
                auth, signals, sandbox, composite, verdict, action
            ),
        })

    return {"risk_scores": risk_scores}


def _build_explanation(
    auth: dict, signals: list[dict], sandbox: dict,
    score: float, verdict: str, action: str,
) -> str:
    """Build human-readable explanation of verdict."""
    parts: list[str] = [f"Risk score: {score:.1f}/100 → {verdict} ({action})."]

    if auth.get("auth_summary") and auth["auth_summary"] != "All checks passed":
        parts.append(f"Auth: {auth['auth_summary']}.")

    signal_types = [s.get("signal_type", "") for s in signals]
    if signal_types:
        parts.append(f"Content signals: {', '.join(signal_types)}.")

    sandbox_verdict = sandbox.get("overall_verdict", "clean")
    if sandbox_verdict != "clean":
        parts.append(f"Sandbox: {sandbox_verdict}.")

    return " ".join(parts)
