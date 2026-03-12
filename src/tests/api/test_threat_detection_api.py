"""API tests for the Threat Detection Agent BFF."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

import threat_detection_agent.api.dependencies as deps
from threat_detection_agent.api.app import app

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


# ── Health ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_healthz(client: AsyncClient):
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Dashboard ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dashboard_empty(client: AsyncClient):
    r = await client.get("/api/v1/dashboard/metrics")
    assert r.status_code == 200
    d = r.json()
    assert d["total_alerts"] == 0
    assert d["rules_deployed"] == 0


# ── Alerts CRUD ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alerts_list_empty(client: AsyncClient):
    r = await client.get("/api/v1/alerts")
    assert r.status_code == 200
    d = r.json()
    assert d["total"] == 0
    assert d["items"] == []


@pytest.mark.asyncio
async def test_alert_create_and_get(client: AsyncClient):
    r = await client.post(
        "/api/v1/alerts",
        params={"severity": "High", "description": "Test alert"},
    )
    assert r.status_code == 201
    alert = r.json()
    aid = alert["alert_id"]
    assert alert["severity"] == "High"

    r2 = await client.get(f"/api/v1/alerts/{aid}")
    assert r2.status_code == 200
    assert r2.json()["alert_id"] == aid


@pytest.mark.asyncio
async def test_alert_not_found(client: AsyncClient):
    r = await client.get("/api/v1/alerts/NOPE")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_alert_update(client: AsyncClient):
    r = await client.post(
        "/api/v1/alerts",
        params={"severity": "Medium"},
    )
    aid = r.json()["alert_id"]
    r2 = await client.put(f"/api/v1/alerts/{aid}", json={"status": "investigating"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "investigating"


@pytest.mark.asyncio
async def test_alert_filter_by_severity(client: AsyncClient):
    await client.post("/api/v1/alerts", params={"severity": "Critical"})
    await client.post("/api/v1/alerts", params={"severity": "Low"})
    r = await client.get("/api/v1/alerts?severity=Critical")
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(i["severity"] == "Critical" for i in items)


@pytest.mark.asyncio
async def test_alert_pagination(client: AsyncClient):
    for _ in range(5):
        await client.post("/api/v1/alerts", params={"severity": "Medium"})
    r = await client.get("/api/v1/alerts?page=1&page_size=2")
    d = r.json()
    assert len(d["items"]) == 2
    assert d["total"] == 5
    assert d["pages"] == 3


@pytest.mark.asyncio
async def test_alert_feedback(client: AsyncClient):
    r = await client.post("/api/v1/alerts", params={"severity": "High"})
    aid = r.json()["alert_id"]
    r2 = await client.post(
        f"/api/v1/alerts/{aid}/feedback",
        json={"analyst_id": "a1", "verdict": "true_positive", "comment": "confirmed"},
    )
    assert r2.status_code == 200
    assert "message" in r2.json()


# ── Rules CRUD ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rules_list_empty(client: AsyncClient):
    r = await client.get("/api/v1/rules")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_rule_create_and_get(client: AsyncClient):
    r = await client.post(
        "/api/v1/rules",
        json={"rule_name": "Test Rule", "severity": "High"},
    )
    assert r.status_code == 201
    rule = r.json()
    assert rule["rule_name"] == "Test Rule"

    rid = rule["rule_id"]
    r2 = await client.get(f"/api/v1/rules/{rid}")
    assert r2.status_code == 200


@pytest.mark.asyncio
async def test_rule_update(client: AsyncClient):
    r = await client.post("/api/v1/rules", json={"rule_name": "R1"})
    rid = r.json()["rule_id"]
    r2 = await client.put(f"/api/v1/rules/{rid}", json={"rule_name": "R1-updated"})
    assert r2.status_code == 200
    assert r2.json()["rule_name"] == "R1-updated"


@pytest.mark.asyncio
async def test_rule_delete(client: AsyncClient):
    r = await client.post("/api/v1/rules", json={"rule_name": "temp"})
    rid = r.json()["rule_id"]
    r2 = await client.delete(f"/api/v1/rules/{rid}")
    assert r2.status_code == 200
    r3 = await client.get(f"/api/v1/rules/{rid}")
    assert r3.status_code == 404


@pytest.mark.asyncio
async def test_rule_test_endpoint(client: AsyncClient):
    r = await client.post("/api/v1/rules", json={"rule_name": "Brute"})
    rid = r.json()["rule_id"]
    r2 = await client.post(
        f"/api/v1/rules/{rid}/test",
        json={"test_events": [{"src_ip": "10.0.0.1"}]},
    )
    assert r2.status_code == 200
    body = r2.json()
    assert "events_tested" in body


# ── Anomalies ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_anomalies_list_empty(client: AsyncClient):
    r = await client.get("/api/v1/anomalies")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_anomaly_create_and_filter(client: AsyncClient):
    r = await client.post(
        "/api/v1/anomalies",
        params={
            "anomaly_type": "login_frequency",
            "anomaly_score": 0.85,
            "baseline_value": 5.0,
            "observed_value": 50.0,
            "entity_type": "user",
            "entity_id": "jdoe",
        },
    )
    assert r.status_code == 201

    r2 = await client.get("/api/v1/anomalies?entity_type=user")
    assert r2.status_code == 200
    assert len(r2.json()) == 1


# ── Coverage ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_coverage_attack(client: AsyncClient):
    r = await client.get("/api/v1/coverage/attack")
    assert r.status_code == 200
    d = r.json()
    assert "total_techniques" in d
    assert "techniques" in d
    assert d["total_techniques"] >= 1


# ── Pipeline ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pipeline_health(client: AsyncClient):
    r = await client.get("/api/v1/pipeline/health")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] in ("healthy", "degraded", "down")
    assert isinstance(d["nodes"], list)


# ── Tuning ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tuning_metrics_empty(client: AsyncClient):
    r = await client.get("/api/v1/tuning/metrics")
    assert r.status_code == 200
    d = r.json()
    assert d["total_feedback"] == 0


@pytest.mark.asyncio
async def test_tuning_after_feedback(client: AsyncClient):
    r = await client.post("/api/v1/alerts", params={"severity": "High"})
    aid = r.json()["alert_id"]
    await client.post(
        f"/api/v1/alerts/{aid}/feedback",
        json={"analyst_id": "a1", "verdict": "true_positive"},
    )
    await client.post(
        f"/api/v1/alerts/{aid}/feedback",
        json={"analyst_id": "a2", "verdict": "false_positive"},
    )
    r2 = await client.get("/api/v1/tuning/metrics")
    d = r2.json()
    assert d["total_feedback"] == 2
    assert d["true_positive_rate"] == 0.5
    assert d["false_positive_rate"] == 0.5


# ── Dashboard with data ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_dashboard_with_alerts(client: AsyncClient):
    await client.post("/api/v1/alerts", params={"severity": "Critical"})
    await client.post("/api/v1/alerts", params={"severity": "High"})
    await client.post("/api/v1/alerts", params={"severity": "High"})

    r = await client.get("/api/v1/dashboard/metrics")
    d = r.json()
    assert d["total_alerts"] == 3
    assert d["critical_alerts"] == 1
    assert d["high_alerts"] == 2
