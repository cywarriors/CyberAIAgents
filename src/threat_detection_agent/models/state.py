"""LangGraph state model for the detection pipeline."""

from __future__ import annotations

from typing import Annotated

from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

from threat_detection_agent.models.alerts import (
    Alert,
    AlertCandidate,
    AnomalyResult,
    FeedbackItem,
    RuleMatch,
)
from threat_detection_agent.models.events import NormalizedEvent, RawEvent


def _merge_lists(left: list, right: list) -> list:
    """Reducer that merges two lists (used by LangGraph state channels)."""
    return left + right


class EventBatchState(BaseModel):
    """
    Shared state that flows through the LangGraph detection graph.

    Each field uses an annotation-based reducer so parallel branches
    (RuleMatch, BehaviorAnomaly) can append results concurrently.
    """

    event_batch_id: str = ""
    raw_events: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    normalized_events: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    matched_rules: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    anomalies: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    alert_candidates: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    final_alerts: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    feedback_queue: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    errors: Annotated[list[str], _merge_lists] = Field(default_factory=list)
