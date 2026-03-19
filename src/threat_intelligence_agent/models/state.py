"""LangGraph state model for the Threat Intelligence Agent."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field


def _merge_lists(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reducer: append-only merge for parallel branches."""
    return left + right


class ThreatIntelState(BaseModel):
    """Central state flowing through the threat-intelligence LangGraph."""

    raw_intel: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    normalized_objects: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    deduplicated_iocs: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    confidence_scores: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    relevance_assessments: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    attck_mappings: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    briefs: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    distribution_results: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    feedback_results: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    processing_errors: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
