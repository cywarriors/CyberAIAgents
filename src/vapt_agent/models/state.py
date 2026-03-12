"""LangGraph state model for the VAPT pipeline."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field


def _merge_lists(left: list, right: list) -> list:
    """Reducer that merges two lists (used by LangGraph state channels)."""
    return left + right


class VAPTState(BaseModel):
    """
    Shared state that flows through the LangGraph VAPT graph.

    Each field uses an annotation-based reducer so nodes can append
    results as data flows through the pipeline.
    """

    engagement_id: str = ""
    roe_authorization: dict = Field(default_factory=dict)
    roe_validated: bool = False
    discovered_assets: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    scan_results: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    validated_exploits: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    attack_paths: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    risk_scores: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    remediation_items: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    report_artifacts: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    published_findings: Annotated[list[dict], _merge_lists] = Field(default_factory=list)
    errors: Annotated[list[str], _merge_lists] = Field(default_factory=list)
