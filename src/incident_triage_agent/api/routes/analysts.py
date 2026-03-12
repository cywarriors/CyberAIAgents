"""Analyst workload endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from incident_triage_agent.api.dependencies import get_store
from incident_triage_agent.api.schemas import AnalystWorkload

router = APIRouter(prefix="/api/v1/analysts", tags=["analysts"])


@router.get("/workload", response_model=list[AnalystWorkload])
async def get_analyst_workload():
    store = get_store()

    analyst_incidents: dict[str, int] = {}
    for inc in store.incidents.values():
        analyst = inc.get("assigned_analyst")
        if analyst:
            analyst_incidents[analyst] = analyst_incidents.get(analyst, 0) + 1

    result: list[AnalystWorkload] = []
    for analyst_id, data in store.analysts.items():
        result.append(
            AnalystWorkload(
                analyst_id=analyst_id,
                analyst_name=data.get("name", analyst_id),
                open_incidents=analyst_incidents.get(analyst_id, 0),
                avg_handling_time_seconds=data.get("avg_handling_time_seconds", 0.0),
                resolved_today=data.get("resolved_today", 0),
            )
        )

    if not result and analyst_incidents:
        for analyst_id, count in analyst_incidents.items():
            result.append(
                AnalystWorkload(
                    analyst_id=analyst_id,
                    analyst_name=analyst_id,
                    open_incidents=count,
                    avg_handling_time_seconds=0.0,
                    resolved_today=0,
                )
            )

    return result
