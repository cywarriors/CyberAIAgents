"""LangGraph shared state for the Identity & Access Monitoring Agent."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel


def _merge_lists(left: list[Any], right: list[Any]) -> list[Any]:
    """LangGraph reducer – append right items to left."""
    if not isinstance(left, list):
        left = []
    if not isinstance(right, list):
        right = [right] if right else []
    return left + right


class IdentityRiskState(BaseModel):
    """State flowing through the identity-risk LangGraph pipeline."""

    batch_id: str = ""

    # FR-01 – ingested events
    raw_auth_events: Annotated[list[dict[str, Any]], _merge_lists] = []
    raw_role_changes: Annotated[list[dict[str, Any]], _merge_lists] = []

    # FR-02/03 – session analysis
    session_profiles: Annotated[list[dict[str, Any]], _merge_lists] = []
    session_anomalies: Annotated[list[dict[str, Any]], _merge_lists] = []

    # FR-04 – privilege changes
    privilege_alerts: Annotated[list[dict[str, Any]], _merge_lists] = []
    sod_violations: Annotated[list[dict[str, Any]], _merge_lists] = []

    # FR-03 – takeover signals
    takeover_signals: Annotated[list[dict[str, Any]], _merge_lists] = []

    # FR-05 – risk scores
    risk_scores: Annotated[list[dict[str, Any]], _merge_lists] = []

    # FR-06 – recommended controls
    recommendations: Annotated[list[dict[str, Any]], _merge_lists] = []

    # FR-07 – alerts / tickets
    alerts: Annotated[list[dict[str, Any]], _merge_lists] = []

    # FR-10 – feedback
    feedback_queue: Annotated[list[dict[str, Any]], _merge_lists] = []

    # Errors
    errors: Annotated[list[dict[str, Any]], _merge_lists] = []
