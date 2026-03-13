"""DetonateURLsAttachmentsNode – sandbox detonation for URLs and attachments (FR-04)."""

from __future__ import annotations

from typing import Any

import structlog

from phishing_defense_agent.integrations.sandbox import (
    detonate_url,
    detonate_attachment,
)

logger = structlog.get_logger(__name__)


def detonate_urls_attachments(state: dict[str, Any]) -> dict[str, Any]:
    """Submit URLs and attachments to sandbox for behavioral analysis.

    Implements FR-04.
    """
    features_list: list[dict] = state.get("email_features", [])

    logger.info("detonate_urls_attachments", email_count=len(features_list))

    sandbox_results: list[dict[str, Any]] = []
    for feat in features_list:
        message_id = feat.get("message_id", "")
        urls = feat.get("urls", [])
        attachment_names = feat.get("attachment_names", [])
        attachment_hashes = feat.get("attachment_hashes", [])

        url_results: list[dict[str, Any]] = []
        for url in urls:
            result = detonate_url(url)
            url_results.append(result)

        attachment_results: list[dict[str, Any]] = []
        for i, name in enumerate(attachment_names):
            file_hash = attachment_hashes[i] if i < len(attachment_hashes) else ""
            result = detonate_attachment(name, file_hash)
            attachment_results.append(result)

        # Determine overall verdict
        all_verdicts = (
            [r.get("sandbox_verdict", "clean") for r in url_results]
            + [r.get("sandbox_verdict", "clean") for r in attachment_results]
        )
        if "malicious" in all_verdicts:
            overall = "malicious"
        elif "suspicious" in all_verdicts:
            overall = "suspicious"
        else:
            overall = "clean"

        sandbox_results.append({
            "message_id": message_id,
            "url_results": url_results,
            "attachment_results": attachment_results,
            "overall_verdict": overall,
            "urls_scanned": len(urls),
            "attachments_scanned": len(attachment_names),
        })

    logger.info("sandbox_detonation_complete", results=len(sandbox_results))
    return {"sandbox_results": sandbox_results}
