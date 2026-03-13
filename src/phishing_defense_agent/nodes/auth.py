"""ValidateSenderAuthNode – SPF/DKIM/DMARC checks, lookalike detection (FR-02)."""

from __future__ import annotations

import re
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Levenshtein-style lookalike patterns
_COMMON_SUBSTITUTIONS: dict[str, str] = {
    "0": "o", "1": "l", "rn": "m", "vv": "w", "cl": "d",
}

# Well-known impersonation targets
_TRUSTED_DOMAINS = frozenset({
    "microsoft.com", "google.com", "apple.com", "amazon.com",
    "paypal.com", "netflix.com", "linkedin.com", "facebook.com",
    "dropbox.com", "adobe.com", "salesforce.com", "docusign.com",
    "zoom.us", "slack.com", "github.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "fedex.com", "ups.com",
    "dhl.com", "usps.com",
})


def _check_spf(headers: dict[str, str]) -> dict[str, Any]:
    """Evaluate SPF status from headers."""
    auth_results = headers.get("Authentication-Results", "")
    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none)", auth_results, re.IGNORECASE)
    status = spf_match.group(1).lower() if spf_match else "none"
    status_map = {"pass": "pass", "fail": "fail", "softfail": "soft_fail", "neutral": "neutral"}
    return {"status": status_map.get(status, "none"), "raw": status}


def _check_dkim(headers: dict[str, str]) -> dict[str, Any]:
    """Evaluate DKIM status from headers."""
    auth_results = headers.get("Authentication-Results", "")
    dkim_match = re.search(r"dkim=(pass|fail|none)", auth_results, re.IGNORECASE)
    status = dkim_match.group(1).lower() if dkim_match else "none"
    return {"status": status, "raw": status}


def _check_dmarc(headers: dict[str, str]) -> dict[str, Any]:
    """Evaluate DMARC status from headers."""
    auth_results = headers.get("Authentication-Results", "")
    dmarc_match = re.search(r"dmarc=(pass|fail|none)", auth_results, re.IGNORECASE)
    status = dmarc_match.group(1).lower() if dmarc_match else "none"
    return {"status": status, "raw": status}


def _normalize_domain(domain: str) -> str:
    """Normalize a domain for comparison (strip confusables)."""
    d = domain.lower().strip(".")
    for fake, real in _COMMON_SUBSTITUTIONS.items():
        d = d.replace(fake, real)
    return d


def _detect_lookalike(sender_domain: str) -> dict[str, Any]:
    """Detect if sender domain is a lookalike of a trusted domain."""
    if not sender_domain:
        return {"is_lookalike": False, "target": ""}

    normalized = _normalize_domain(sender_domain)
    sender_lower = sender_domain.lower()

    for trusted in _TRUSTED_DOMAINS:
        if sender_lower == trusted:
            # Exact match – not a lookalike
            continue
        # Check normalized match
        if normalized == _normalize_domain(trusted):
            return {"is_lookalike": True, "target": trusted}
        # Check substring containment (e.g. microsoft-support.com)
        trusted_base = trusted.split(".")[0]
        sender_base = sender_lower.split(".")[0]
        if len(trusted_base) >= 5 and trusted_base in sender_base and sender_lower != trusted:
            return {"is_lookalike": True, "target": trusted}
        # Check transposition / extra char (edit distance 1)
        if len(sender_base) == len(trusted_base) and sender_base != trusted_base:
            diffs = sum(1 for a, b in zip(sender_base, trusted_base) if a != b)
            if diffs == 1:
                return {"is_lookalike": True, "target": trusted}

    return {"is_lookalike": False, "target": ""}


def _compute_sender_reputation(
    spf: dict, dkim: dict, dmarc: dict, domain_age_days: int, is_lookalike: bool,
) -> float:
    """Compute a 0-100 sender reputation score (100 = fully trusted)."""
    score = 50.0  # baseline

    # Authentication bonuses / penalties
    if spf["status"] == "pass":
        score += 15
    elif spf["status"] == "fail":
        score -= 20
    elif spf["status"] == "soft_fail":
        score -= 10

    if dkim["status"] == "pass":
        score += 15
    elif dkim["status"] == "fail":
        score -= 20

    if dmarc["status"] == "pass":
        score += 15
    elif dmarc["status"] == "fail":
        score -= 25

    # Domain age
    if domain_age_days >= 0:
        if domain_age_days < 7:
            score -= 25
        elif domain_age_days < 30:
            score -= 15
        elif domain_age_days < 90:
            score -= 5
        elif domain_age_days > 365:
            score += 5

    # Lookalike penalty
    if is_lookalike:
        score -= 30

    return max(0.0, min(100.0, score))


def validate_sender_auth(state: dict[str, Any]) -> dict[str, Any]:
    """Validate SPF/DKIM/DMARC and detect lookalike domains.

    Implements FR-02.
    """
    features_list: list[dict] = state.get("email_features", [])

    logger.info("validate_sender_auth", email_count=len(features_list))

    auth_results: list[dict[str, Any]] = []
    for feat in features_list:
        headers = feat.get("headers", {})
        sender_domain = feat.get("sender_domain", "")
        domain_age = feat.get("domain_age_days", -1)

        spf = _check_spf(headers)
        dkim = _check_dkim(headers)
        dmarc = _check_dmarc(headers)
        lookalike = _detect_lookalike(sender_domain)

        reputation = _compute_sender_reputation(
            spf, dkim, dmarc, domain_age, lookalike["is_lookalike"]
        )

        summary_parts: list[str] = []
        if spf["status"] == "fail":
            summary_parts.append("SPF FAIL")
        if dkim["status"] == "fail":
            summary_parts.append("DKIM FAIL")
        if dmarc["status"] == "fail":
            summary_parts.append("DMARC FAIL")
        if lookalike["is_lookalike"]:
            summary_parts.append(f"Lookalike of {lookalike['target']}")

        auth_results.append({
            "message_id": feat.get("message_id", ""),
            "spf_status": spf["status"],
            "dkim_status": dkim["status"],
            "dmarc_status": dmarc["status"],
            "spf_domain": sender_domain,
            "dkim_domain": sender_domain,
            "dmarc_domain": sender_domain,
            "is_lookalike_domain": lookalike["is_lookalike"],
            "lookalike_target": lookalike["target"],
            "domain_age_days": domain_age,
            "sender_reputation_score": reputation,
            "auth_summary": "; ".join(summary_parts) if summary_parts else "All checks passed",
        })

    return {"auth_results": auth_results}
