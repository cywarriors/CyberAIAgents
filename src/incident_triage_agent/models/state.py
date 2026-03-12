"""LangGraph state model for the triage pipeline."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field


def _merge_lists(left: list, right: list) -> list:
    """Reducer that merges two lists (used by LangGraph state channels)."""
    return left + right


class TriageState(BaseModel):
    """
    Shared state that flows through the LangGraph triage graph.

    Matches §12.1 state model definition:
      raw_alerts, entity_context, correlations, priority_score,
      triage_summary, recommended_actions, case_id
    """

    # Batch tracking
    triage_batch_id: str = ""

    # Ingested alerts (FR-01)
    raw_alerts: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Entity enrichment context (FR-03)
    entity_context: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Correlation groups (FR-02)
    correlations: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Priority scoring (FR-04)
    priority_scores: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Classification (FR-05)
    classifications: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Triage summaries (FR-06)
    triage_summaries: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Recommended actions (FR-07)
    recommended_actions: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Incident timeline (FR-10)
    incident_timeline: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Final triaged incidents
    triaged_incidents: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Case / ticket IDs (FR-08)
    case_ids: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Feedback queue (FR-09)
    feedback_queue: Annotated[list[dict], _merge_lists] = Field(default_factory=list)

    # Errors
    errors: Annotated[list[str], _merge_lists] = Field(default_factory=list)
