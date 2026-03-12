"""Incident CRUD, actions, and investigation endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from incident_triage_agent.api.dependencies import get_store
from incident_triage_agent.api.schemas import (
    CorrelationEdge,
    CorrelationGraph,
    CorrelationNode,
    IncidentFeedback,
    IncidentResponse,
    IncidentUpdate,
    MessageResponse,
    PaginatedIncidents,
    PlaybookRecommendation,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.get("", response_model=PaginatedIncidents)
async def list_incidents(
    priority: list[str] | None = Query(None),
    severity: str | None = None,
    status: str | None = None,
    assigned_analyst: str | None = None,
    classification: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    store = get_store()
    items = list(store.incidents.values())

    if priority:
        items = [i for i in items if i.get("priority") in priority]
    if severity:
        items = [i for i in items if i.get("severity") == severity]
    if status:
        items = [i for i in items if i.get("status") == status]
    if assigned_analyst:
        items = [i for i in items if i.get("assigned_analyst") == assigned_analyst]
    if classification:
        items = [i for i in items if i.get("classification") == classification]
    if search:
        q = search.lower()
        items = [i for i in items if q in i.get("triage_summary", "").lower() or q in i.get("incident_id", "").lower()]

    items.sort(key=lambda i: ({"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(i.get("priority", "P4"), 4), i.get("timestamp", "")))
    total = len(items)
    pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    return PaginatedIncidents(
        items=[IncidentResponse(**i) for i in items[start : start + page_size]],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post("", response_model=IncidentResponse, status_code=201)
async def create_incident(
    priority: str = "P3",
    severity: str = "Medium",
    classification: str = "unknown",
    triage_summary: str = "",
):
    """Create a new incident (for testing / manual injection)."""
    store = get_store()
    iid = f"INC-{uuid.uuid4().hex[:8]}"
    cid = f"CASE-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc).isoformat()
    sla_map = {"P1": 900, "P2": 1800, "P3": 3600, "P4": 7200}
    incident = {
        "incident_id": iid,
        "case_id": cid,
        "timestamp": now,
        "priority": priority,
        "classification": classification,
        "severity": severity,
        "confidence": 50,
        "triage_summary": triage_summary,
        "status": "new",
        "assigned_analyst": "",
        "sla_remaining_seconds": sla_map.get(priority, 3600),
        "alert_ids": [],
        "entity_profiles": [],
        "correlation_groups": [],
        "recommended_actions": [],
        "timeline": [{"event": "created", "timestamp": now}],
        "mitre_technique_ids": [],
        "mitre_tactics": [],
        "evidence": [],
        "analyst_notes": "",
    }
    store.incidents[iid] = incident
    return IncidentResponse(**incident)


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str):
    store = get_store()
    incident = store.incidents.get(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return IncidentResponse(**incident)


@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(incident_id: str, payload: IncidentUpdate):
    store = get_store()
    incident = store.incidents.get(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    now = datetime.now(timezone.utc).isoformat()
    for k, v in payload.model_dump(exclude_none=True).items():
        incident[k] = v
    incident.setdefault("timeline", []).append({"event": "updated", "timestamp": now})
    return IncidentResponse(**incident)


@router.delete("/{incident_id}", response_model=MessageResponse)
async def delete_incident(incident_id: str):
    store = get_store()
    if incident_id not in store.incidents:
        raise HTTPException(404, "Incident not found")
    del store.incidents[incident_id]
    return MessageResponse(message="Incident deleted")


@router.post("/{incident_id}/feedback", response_model=MessageResponse)
async def submit_feedback(incident_id: str, payload: IncidentFeedback):
    store = get_store()
    if incident_id not in store.incidents:
        raise HTTPException(404, "Incident not found")
    store.feedback.append(
        {
            "incident_id": incident_id,
            "analyst_id": payload.analyst_id,
            "verdict": payload.verdict.value,
            "corrected_priority": payload.corrected_priority,
            "corrected_classification": payload.corrected_classification,
            "comment": payload.comment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    return MessageResponse(message="Feedback recorded")


@router.get("/{incident_id}/correlations", response_model=CorrelationGraph)
async def get_correlations(incident_id: str):
    store = get_store()
    incident = store.incidents.get(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")

    nodes: list[CorrelationNode] = [
        CorrelationNode(
            node_id=incident_id,
            node_type="incident",
            label=f"Incident {incident_id}",
            severity=incident.get("severity", "Medium"),
        )
    ]
    edges: list[CorrelationEdge] = []

    for aid in incident.get("alert_ids", []):
        nodes.append(
            CorrelationNode(
                node_id=aid,
                node_type="alert",
                label=f"Alert {aid}",
                severity=incident.get("severity", "Medium"),
            )
        )
        edges.append(
            CorrelationEdge(source=incident_id, target=aid, method="entity")
        )

    return CorrelationGraph(nodes=nodes, edges=edges)


@router.get("/{incident_id}/playbooks", response_model=list[PlaybookRecommendation])
async def get_playbooks(incident_id: str):
    store = get_store()
    incident = store.incidents.get(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")

    classification = incident.get("classification", "unknown")
    playbooks = _generate_playbooks(classification)
    return playbooks


def _generate_playbooks(classification: str) -> list[PlaybookRecommendation]:
    """Generate context-aware playbook recommendations."""
    catalog: dict[str, list[PlaybookRecommendation]] = {
        "malware": [
            PlaybookRecommendation(
                playbook_id="PB-MAL-001",
                name="Malware Containment",
                description="Isolate affected host, collect forensic image, run AV scan.",
                confidence=0.92,
                steps=["Isolate host from network", "Collect memory dump", "Run full AV scan", "Notify SOC manager"],
                action_type="contain",
            ),
        ],
        "phishing": [
            PlaybookRecommendation(
                playbook_id="PB-PHI-001",
                name="Phishing Response",
                description="Block sender, remove emails, reset credentials if clicked.",
                confidence=0.88,
                steps=["Block sender domain", "Purge phishing emails from mailboxes", "Reset impacted credentials", "User awareness alert"],
                action_type="contain",
            ),
        ],
        "credential_abuse": [
            PlaybookRecommendation(
                playbook_id="PB-CRED-001",
                name="Credential Compromise Response",
                description="Reset passwords, revoke sessions, enable MFA.",
                confidence=0.85,
                steps=["Force password reset", "Revoke active sessions", "Enable MFA", "Review access logs"],
                action_type="contain",
            ),
        ],
    }
    default = [
        PlaybookRecommendation(
            playbook_id="PB-GEN-001",
            name="General Investigation",
            description="Standard investigation playbook for unclassified incidents.",
            confidence=0.60,
            steps=["Gather context", "Identify affected assets", "Assess blast radius", "Escalate if P1/P2"],
            action_type="investigate",
        ),
    ]
    return catalog.get(classification, default)
