"""ExtractEmailFeaturesNode – parse headers, body, URLs, attachments (FR-01)."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)

# Common URL pattern
_URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# Known URL shortener domains
_SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
})


def _extract_urls(text: str) -> list[str]:
    """Extract unique URLs from text."""
    if not text:
        return []
    urls = _URL_PATTERN.findall(text)
    seen: set[str] = set()
    unique: list[str] = []
    for url in urls:
        url = url.rstrip(".,;:!?)")
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def _extract_domain(email_addr: str) -> str:
    """Extract domain part from email address."""
    if "@" in email_addr:
        return email_addr.rsplit("@", 1)[1].lower()
    return ""


def _is_internal(sender_domain: str, recipient_domains: list[str]) -> bool:
    """Check if email is internal (sender domain matches a recipient domain)."""
    if not sender_domain or not recipient_domains:
        return False
    return sender_domain in recipient_domains


def extract_email_features(state: dict[str, Any]) -> dict[str, Any]:
    """Parse raw emails into structured feature dicts.

    Implements FR-01: inspect inbound and internal emails for phishing indicators.
    """
    raw_emails: list[dict] = state.get("raw_emails", [])
    batch_id = state.get("batch_id") or f"phish-{uuid.uuid4().hex[:12]}"

    logger.info("extract_email_features", batch_id=batch_id, count=len(raw_emails))

    features: list[dict[str, Any]] = []
    for email in raw_emails:
        message_id = email.get("message_id") or f"msg-{uuid.uuid4().hex[:12]}"
        sender = email.get("sender_address", email.get("from", ""))
        sender_domain = _extract_domain(sender)

        recipients = email.get("recipient_addresses", email.get("to", []))
        if isinstance(recipients, str):
            recipients = [r.strip() for r in recipients.split(",")]
        recipient_domains = [_extract_domain(r) for r in recipients]

        body_text = email.get("body_text", email.get("body", ""))
        body_html = email.get("body_html", "")

        # Extract URLs from both text and HTML body
        urls = _extract_urls(body_text) + _extract_urls(body_html)
        urls = list(dict.fromkeys(urls))  # dedupe preserving order

        attachment_names = email.get("attachment_names", [])
        attachment_hashes = email.get("attachment_hashes", [])
        if not attachment_hashes and attachment_names:
            attachment_hashes = [
                hashlib.sha256(name.encode()).hexdigest()[:16]
                for name in attachment_names
            ]

        feature = {
            "message_id": message_id,
            "subject": email.get("subject", ""),
            "sender_address": sender,
            "sender_display_name": email.get("sender_display_name", email.get("from_name", "")),
            "reply_to": email.get("reply_to", ""),
            "return_path": email.get("return_path", ""),
            "recipient_addresses": recipients,
            "cc_addresses": email.get("cc_addresses", []),
            "received_timestamp": email.get(
                "received_timestamp", datetime.now(timezone.utc).isoformat()
            ),
            "headers": email.get("headers", {}),
            "body_text": body_text,
            "body_html": body_html,
            "urls": urls,
            "url_domains": list({urlparse(u).netloc for u in urls if urlparse(u).netloc}),
            "has_shortened_urls": any(
                urlparse(u).netloc.lower() in _SHORTENER_DOMAINS for u in urls
            ),
            "attachment_names": attachment_names,
            "attachment_hashes": attachment_hashes,
            "attachment_sizes": email.get("attachment_sizes", []),
            "attachment_count": len(attachment_names),
            "is_internal": _is_internal(sender_domain, recipient_domains),
            "sender_domain": sender_domain,
            "_batch_id": batch_id,
            "_processed_at": datetime.now(timezone.utc).isoformat(),
        }
        features.append(feature)

    return {"batch_id": batch_id, "email_features": features}
