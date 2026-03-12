"""API tests for the Incident Triage Agent BFF."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

import incident_triage_agent.api.dependencies as deps
from incident_triage_agent.api.app import app

BASE = "http://test"


@pytest.fixture(autouse=True)
def _reset_store():
    deps._store_instance = None
    yield
    deps._store_instance = None


@pytest.fixture()
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE) as c:
        yield c


async def _create_incident(
    client: AsyncClient,
    priority: str = "P3",
    classification: str = "unknown",
    severity: str = "Medium",
) -> dict:
    r = await client.post(
        "/api/v1/incidents",
        params={"priority": priority, "classification": classification, "severity": severity},
    )
    assert r.status_code == 201
    return r.json()


# ── Health ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_healthz(client: AsyncClient):
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Dashboard ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dashboard_empty(client: AsyncClient):
    r = await client.get("/api/v1/dashboard/summary")
    assert r.status_code == 200
    d = r.json()
    assert d["open_incidents"] == 0
    assert d["p1_count"] == 0


@pytest.mark.asyncio
async def test_dashboard_with_incidents(client: AsyncClient):
    await _create_incident(client, "P1", "malware")
    await _create_incident(client, "P2", "phishing")
    await _create_incident(client, "P1", "credential_abuse")

    r = await client.get("/api/v1/dashboard/summary")
    d = r.json()
    assert d["open_incidents"] == 3
    assert d["p1_count"] == 2
    assert d["p2_count"] == 1
    assert d["incidents_today"] == 3


# ── Incidents CRUD ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incidents_list_empty(client: AsyncClient):
    r = await client.get("/api/v1/incidents")
    assert r.status_code == 200
    d = r.json()
    assert d["total"] == 0
    assert d["items"] == []


@pytest.mark.asyncio
async def test_incident_create_and_get(client: AsyncClient):
    inc = await _create_incident(client, "P2", "malware", "High")
    iid = inc["incident_id"]
    assert inc["priority"] == "P2"
    assert inc["classification"] == "malware"
    assert inc["sla_remaining_seconds"] == 1800

    r = await client.get(f"/api/v1/incidents/{iid}")
    assert r.status_code == 200
    assert r.json()["incident_id"] == iid


@pytest.mark.asyncio
async def test_incident_not_found(client: AsyncClient):
    r = await client.get("/api/v1/incidents/NOPE")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_incident_update(client: AsyncClient):
    inc = await _create_incident(client)
    iid = inc["incident_id"]
    r = await client.put(
        f"/api/v1/incidents/{iid}",
        json={"status": "assigned", "assigned_analyst": "analyst-1"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "assigned"
    assert body["assigned_analyst"] == "analyst-1"
    assert len(body["timeline"]) == 2  # created + updated


@pytest.mark.asyncio
async def test_incident_delete(client: AsyncClient):
    inc = await _create_incident(client)
    iid = inc["incident_id"]
    r = await client.delete(f"/api/v1/incidents/{iid}")
    assert r.status_code == 200
    r2 = await client.get(f"/api/v1/incidents/{iid}")
    assert r2.status_code == 404


@pytest.mark.asyncio
async def test_incident_filter_by_priority(client: AsyncClient):
    await _create_incident(client, "P1")
    await _create_incident(client, "P3")
    r = await client.get("/api/v1/incidents?priority=P1")
    items = r.json()["items"]
    assert all(i["priority"] == "P1" for i in items)


@pytest.mark.asyncio
async def test_incident_filter_by_status(client: AsyncClient):
    inc = await _create_incident(client)
    iid = inc["incident_id"]
    await client.put(f"/api/v1/incidents/{iid}", json={"status": "escalated"})
    r = await client.get("/api/v1/incidents?status=escalated")
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["status"] == "escalated"


@pytest.mark.asyncio
async def test_incident_pagination(client: AsyncClient):
    for _ in range(5):
        await _create_incident(client)
    r = await client.get("/api/v1/incidents?page=1&page_size=2")
    d = r.json()
    assert len(d["items"]) == 2
    assert d["total"] == 5
    assert d["pages"] == 3


# ── Feedback ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incident_feedback(client: AsyncClient):
    inc = await _create_incident(client)
    iid = inc["incident_id"]
    r = await client.post(
        f"/api/v1/incidents/{iid}/feedback",
        json={"analyst_id": "a1", "verdict": "true_positive", "comment": "confirmed"},
    )
    assert r.status_code == 200
    assert "message" in r.json()


@pytest.mark.asyncio
async def test_feedback_not_found(client: AsyncClient):
    r = await client.post(
        "/api/v1/incidents/NOPE/feedback",
        json={"analyst_id": "a1", "verdict": "false_positive"},
    )
    assert r.status_code == 404


# ── Correlations ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_correlations(client: AsyncClient):
    inc = await _create_incident(client)
    iid = inc["incident_id"]
    r = await client.get(f"/api/v1/incidents/{iid}/correlations")
    assert r.status_code == 200
    graph = r.json()
    assert len(graph["nodes"]) >= 1
    assert graph["nodes"][0]["node_type"] == "incident"


@pytest.mark.asyncio
async def test_correlations_not_found(client: AsyncClient):
    r = await client.get("/api/v1/incidents/NOPE/correlations")
    assert r.status_code == 404


# ── Playbooks ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_playbooks_malware(client: AsyncClient):
    inc = await _create_incident(client, classification="malware")
    iid = inc["incident_id"]
    r = await client.get(f"/api/v1/incidents/{iid}/playbooks")
    assert r.status_code == 200
    pbs = r.json()
    assert len(pbs) >= 1
    assert pbs[0]["name"] == "Malware Containment"


@pytest.mark.asyncio
async def test_playbooks_phishing(client: AsyncClient):
    inc = await _create_incident(client, classification="phishing")
    r = await client.get(f"/api/v1/incidents/{inc['incident_id']}/playbooks")
    pbs = r.json()
    assert pbs[0]["name"] == "Phishing Response"


@pytest.mark.asyncio
async def test_playbooks_default(client: AsyncClient):
    inc = await _create_incident(client, classification="unknown")
    r = await client.get(f"/api/v1/incidents/{inc['incident_id']}/playbooks")
    pbs = r.json()
    assert pbs[0]["name"] == "General Investigation"


@pytest.mark.asyncio
async def test_playbooks_not_found(client: AsyncClient):
    r = await client.get("/api/v1/incidents/NOPE/playbooks")
    assert r.status_code == 404


# ── Analyst Workload ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyst_workload_empty(client: AsyncClient):
    r = await client.get("/api/v1/analysts/workload")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_analyst_workload_after_assign(client: AsyncClient):
    inc = await _create_incident(client)
    await client.put(
        f"/api/v1/incidents/{inc['incident_id']}",
        json={"status": "assigned", "assigned_analyst": "analyst-1"},
    )
    r = await client.get("/api/v1/analysts/workload")
    workload = r.json()
    assert len(workload) >= 1
    assert workload[0]["analyst_id"] == "analyst-1"
    assert workload[0]["open_incidents"] == 1


# ── Triage Metrics ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_triage_metrics_empty(client: AsyncClient):
    r = await client.get("/api/v1/triage/metrics")
    assert r.status_code == 200
    d = r.json()
    assert d["total_triaged"] == 0


@pytest.mark.asyncio
async def test_triage_metrics_with_feedback(client: AsyncClient):
    inc = await _create_incident(client)
    iid = inc["incident_id"]
    await client.post(
        f"/api/v1/incidents/{iid}/feedback",
        json={"analyst_id": "a1", "verdict": "true_positive"},
    )
    await client.post(
        f"/api/v1/incidents/{iid}/feedback",
        json={"analyst_id": "a2", "verdict": "false_positive"},
    )
    r = await client.get("/api/v1/triage/metrics")
    d = r.json()
    assert d["total_triaged"] == 1
    assert d["true_positive_rate"] == 50.0
    assert d["false_positive_rate"] == 50.0


@pytest.mark.asyncio
async def test_triage_escalation_rate(client: AsyncClient):
    inc1 = await _create_incident(client)
    inc2 = await _create_incident(client)
    await client.put(
        f"/api/v1/incidents/{inc1['incident_id']}",
        json={"status": "escalated"},
    )
    r = await client.get("/api/v1/triage/metrics")
    d = r.json()
    assert d["escalation_rate"] == 50.0
