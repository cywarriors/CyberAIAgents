"""LangGraph state model – shared state through phishing verdict pipeline."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field


def _merge_lists(left: list, right: list) -> list:
    """Reducer that merges two lists (for LangGraph state channels)."""
    return left + right


class PhishingVerdictState(BaseModel):
    """State flowing through phishing-verdict graph."""

    # Batch tracking
    batch_id: str = ""

    # Raw email payloads
    raw_emails: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # Extracted email features / metadata
    email_features: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # Sender authentication results
    auth_results: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # NLP content analysis signals
    content_signals: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # Sandbox detonation results (URLs + attachments)
    sandbox_results: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # Combined risk scores
    risk_scores: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # Final verdicts with actions
    verdicts: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # IOCs extracted for sharing
    extracted_iocs: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # Notifications sent
    notifications: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # Feedback queue
    feedback_queue: Annotated[list[dict[str, Any]], _merge_lists] = Field(
        default_factory=list
    )

    # Errors
    errors: Annotated[list[str], _merge_lists] = Field(default_factory=list)
