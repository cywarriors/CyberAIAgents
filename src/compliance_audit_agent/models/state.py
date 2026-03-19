"""LangGraph state model for the Compliance and Audit Agent."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field


def _merge_lists(
    left: list[dict[str, Any]], right: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    return left + right


def _merge_dicts(
    left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    merged = dict(left)
    merged.update(right)
    return merged


class ComplianceState(BaseModel):
    """Central state flowing through the compliance-audit LangGraph."""

    evidence_items: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    control_mappings: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    effectiveness_scores: Annotated[dict[str, Any], _merge_dicts] = Field(default_factory=dict)
    gaps: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    framework_scores: Annotated[dict[str, Any], _merge_dicts] = Field(default_factory=dict)
    audit_packs: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    drift_alerts: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    remediation_tickets: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
    processing_errors: Annotated[list[dict[str, Any]], _merge_lists] = Field(default_factory=list)
