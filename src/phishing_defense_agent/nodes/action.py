"""ApplyMailActionNode – execute verdict: allow / warn / quarantine / block (FR-05/06/07)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def apply_mail_action(state: dict[str, Any]) -> dict[str, Any]:
    """Execute the appropriate mail action based on verdict.

    Implements FR-05 (verdict), FR-06 (warning banners), FR-07 (quarantine).
    """
    risk_scores: list[dict] = state.get("risk_scores", [])
    features_list: list[dict] = state.get("email_features", [])

    feat_by_id = {f["message_id"]: f for f in features_list}

    logger.info("apply_mail_action", count=len(risk_scores))

    verdicts: list[dict[str, Any]] = []
    iocs: list[dict[str, Any]] = []

    for scored in risk_scores:
        message_id = scored["message_id"]
        action = scored["action"]
        verdict = scored["verdict"]
        feat = feat_by_id.get(message_id, {})

        verdict_record: dict[str, Any] = {
            "message_id": message_id,
            "risk_score": scored["risk_score"],
            "verdict": verdict,
            "action": action,
            "confidence": scored["confidence"],
            "explanation": scored["explanation"],
            "components": scored["components"],
            "subject": feat.get("subject", ""),
            "sender_address": feat.get("sender_address", ""),
            "recipient_addresses": feat.get("recipient_addresses", []),
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

        if action == "quarantine":
            verdict_record["quarantine_id"] = f"quar-{uuid.uuid4().hex[:12]}"
            verdict_record["quarantine_status"] = "quarantined"
            logger.info("email_quarantined", message_id=message_id)
        elif action == "block":
            verdict_record["quarantine_status"] = "blocked"
            logger.info("email_blocked", message_id=message_id)
        elif action == "warn":
            verdict_record["warning_applied"] = True
            logger.info("warning_banner_applied", message_id=message_id)
        else:
            verdict_record["quarantine_status"] = "allowed"

        verdicts.append(verdict_record)

        # Extract IOCs from blocked/quarantined emails (FR-09)
        if action in ("block", "quarantine"):
            # URLs
            for url in feat.get("urls", []):
                iocs.append({
                    "ioc_type": "url",
                    "ioc_value": url,
                    "source_message_id": message_id,
                    "confidence": scored["confidence"],
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "tags": [verdict, action],
                })
            # Sender domain
            sender_domain = feat.get("sender_domain", "")
            if sender_domain:
                iocs.append({
                    "ioc_type": "domain",
                    "ioc_value": sender_domain,
                    "source_message_id": message_id,
                    "confidence": scored["confidence"],
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "tags": [verdict, action],
                })
            # Attachment hashes
            for h in feat.get("attachment_hashes", []):
                iocs.append({
                    "ioc_type": "file_hash",
                    "ioc_value": h,
                    "source_message_id": message_id,
                    "confidence": scored["confidence"],
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "tags": [verdict, action],
                })

    logger.info("mail_actions_applied", verdicts=len(verdicts), iocs_extracted=len(iocs))
    return {"verdicts": verdicts, "extracted_iocs": iocs}
