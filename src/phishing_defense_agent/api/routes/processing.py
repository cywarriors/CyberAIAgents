"""Pipeline processing endpoint."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException

from phishing_defense_agent.api.dependencies import get_store
from phishing_defense_agent.api.schemas import ProcessEmailsRequest
from phishing_defense_agent.graph import get_compiled_graph

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/process", tags=["processing"])


@router.post("")
async def process_emails(body: ProcessEmailsRequest):
    """Run phishing verdict pipeline on submitted emails."""
    try:
        graph = get_compiled_graph()
        result = graph.invoke({"raw_emails": body.emails})

        _persist_results(result)

        verdicts = result.get("verdicts", [])
        return {
            "message": "Pipeline completed",
            "emails_processed": len(body.emails),
            "verdicts_issued": len(verdicts),
            "quarantined": sum(1 for v in verdicts if v.get("action") == "quarantine"),
            "blocked": sum(1 for v in verdicts if v.get("action") == "block"),
            "warned": sum(1 for v in verdicts if v.get("action") == "warn"),
            "allowed": sum(1 for v in verdicts if v.get("action") == "allow"),
        }
    except Exception:
        logger.exception("Pipeline execution failed")
        raise HTTPException(status_code=500, detail="Pipeline execution failed")


def _persist_results(result: dict[str, Any]) -> None:
    """Persist pipeline results to in-memory store."""
    store = get_store()

    for v in result.get("verdicts", []):
        message_id = v.get("message_id", "")
        store.verdicts[message_id] = v

        # Add to quarantine if applicable
        qid = v.get("quarantine_id")
        if qid:
            store.quarantine[qid] = {
                "quarantine_id": qid,
                "message_id": message_id,
                "subject": v.get("subject", ""),
                "sender_address": v.get("sender_address", ""),
                "recipient_addresses": v.get("recipient_addresses", []),
                "risk_score": v.get("risk_score", 0),
                "verdict": v.get("verdict", "malicious"),
                "confidence": v.get("confidence", 0),
                "status": "quarantined",
                "quarantined_at": datetime.now(timezone.utc).isoformat(),
                "reviewed_by": "",
                "explanation": v.get("explanation", ""),
            }
