"""Tests for VAPT Agent BFF API endpoints."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from vapt_agent.api.app import app
import vapt_agent.api.dependencies as deps


@pytest.fixture(autouse=True)
def _reset_store():
    """Clear in-memory store before each test."""
    deps._store_instance = None
    yield
    deps._store_instance = None


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ── Helper to create an engagement (used by many tests) ──────────

ROE_PAYLOAD = {
    "scope_ips": ["10.0.0.0/24"],
    "scope_domains": [],
    "scope_cloud_accounts": [],
    "exclusions": [],
    "allow_destructive": False,
}


async def _create_engagement(client: AsyncClient, name: str = "Test Pentest"):
    r = await client.post(
        "/api/v1/engagements",
        json={"name": name, "roe": ROE_PAYLOAD},
    )
    assert r.status_code == 201
    return r.json()


# ── Healthz ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_healthz(client: AsyncClient):
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Dashboard ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dashboard_summary_empty(client: AsyncClient):
    r = await client.get("/api/v1/dashboard/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["active_engagements"] == 0
    assert body["total_findings"] == 0


# ── Engagements CRUD ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_engagement_lifecycle(client: AsyncClient):
    # Create
    eng = await _create_engagement(client)
    eng_id = eng["id"]
    assert eng["name"] == "Test Pentest"
    assert eng["status"] == "draft"

    # List
    r = await client.get("/api/v1/engagements")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # Get
    r = await client.get(f"/api/v1/engagements/{eng_id}")
    assert r.status_code == 200
    assert r.json()["id"] == eng_id

    # Update
    r = await client.put(
        f"/api/v1/engagements/{eng_id}",
        json={"name": "Updated", "status": "in_progress"},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "Updated"
    assert r.json()["status"] == "in_progress"

    # Delete
    r = await client.delete(f"/api/v1/engagements/{eng_id}")
    assert r.status_code == 200

    # Verify deleted
    r = await client.get(f"/api/v1/engagements/{eng_id}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_engagement_not_found(client: AsyncClient):
    r = await client.get("/api/v1/engagements/nonexistent")
    assert r.status_code == 404


# ── RoE ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_roe_operations(client: AsyncClient):
    eng = await _create_engagement(client, "RoE Test")
    eng_id = eng["id"]

    # Get RoE
    r = await client.get(f"/api/v1/engagements/{eng_id}/roe")
    assert r.status_code == 200
    assert "scope_ips" in r.json()

    # Update RoE
    roe = {
        "scope_ips": ["192.168.1.0/24"],
        "scope_domains": ["example.com"],
        "scope_cloud_accounts": [],
        "exclusions": ["192.168.1.1"],
        "allow_destructive": True,
    }
    r = await client.put(f"/api/v1/engagements/{eng_id}/roe", json=roe)
    assert r.status_code == 200
    assert r.json()["allow_destructive"] is True


# ── Findings ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_findings_empty(client: AsyncClient):
    r = await client.get("/api/v1/findings")
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0


# ── Scans ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_lifecycle(client: AsyncClient):
    eng = await _create_engagement(client, "Scan Test")
    eng_id = eng["id"]

    # Create scan
    r = await client.post(
        "/api/v1/scans",
        json={
            "engagement_id": eng_id,
            "targets": ["10.0.0.1"],
        },
    )
    assert r.status_code == 201
    scan = r.json()
    assert scan["status"] == "running"

    # List
    r = await client.get("/api/v1/scans")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # Abort
    r = await client.post(f"/api/v1/scans/{scan['id']}/abort")
    assert r.status_code == 200
    assert r.json()["message"] == "Scan aborted"


@pytest.mark.asyncio
async def test_scan_requires_valid_engagement(client: AsyncClient):
    r = await client.post(
        "/api/v1/scans",
        json={
            "engagement_id": "nonexistent",
            "targets": ["10.0.0.1"],
        },
    )
    assert r.status_code == 404


# ── Attack Paths ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_attack_paths_empty(client: AsyncClient):
    r = await client.get("/api/v1/attack-paths")
    assert r.status_code == 200
    assert r.json() == []


# ── Exploits ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_exploit_catalog(client: AsyncClient):
    r = await client.get("/api/v1/exploits")
    assert r.status_code == 200
    modules = r.json()
    assert len(modules) >= 5
    assert all("id" in m for m in modules)


@pytest.mark.asyncio
async def test_exploit_execute_safe(client: AsyncClient):
    r = await client.post(
        "/api/v1/exploits/mod-sqli-blind/execute",
        json={"target_asset_id": "asset-1", "finding_id": "finding-1"},
    )
    assert r.status_code == 202
    body = r.json()
    assert body["success"] is True
    assert body["module_id"] == "mod-sqli-blind"


@pytest.mark.asyncio
async def test_exploit_destructive_requires_approval(client: AsyncClient):
    r = await client.post(
        "/api/v1/exploits/mod-rce-deserial/execute",
        json={"target_asset_id": "asset-1", "finding_id": "finding-1"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_exploit_destructive_with_approval(client: AsyncClient):
    r = await client.post(
        "/api/v1/exploits/mod-rce-deserial/execute",
        json={
            "target_asset_id": "asset-1",
            "finding_id": "finding-1",
            "approval_token": "approved-by-lead",
        },
    )
    assert r.status_code == 202
    assert r.json()["success"] is True


@pytest.mark.asyncio
async def test_exploit_module_not_found(client: AsyncClient):
    r = await client.post(
        "/api/v1/exploits/nonexistent/execute",
        json={"target_asset_id": "a", "finding_id": "f"},
    )
    assert r.status_code == 404


# ── Reports ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_report_lifecycle(client: AsyncClient):
    eng = await _create_engagement(client, "Report Test")
    eng_id = eng["id"]

    # Create report
    r = await client.post(
        "/api/v1/reports",
        json={
            "engagement_id": eng_id,
            "report_type": "executive",
        },
    )
    assert r.status_code == 201
    report = r.json()
    assert report["status"] == "completed"
    assert report["download_url"].startswith("/api/v1/reports/")

    # List
    r = await client.get("/api/v1/reports")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # Delete
    r = await client.delete(f"/api/v1/reports/{report['id']}")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_report_requires_engagement(client: AsyncClient):
    r = await client.post(
        "/api/v1/reports",
        json={
            "engagement_id": "nonexistent",
            "report_type": "technical",
        },
    )
    assert r.status_code == 404


# ── Compliance ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_compliance_lifecycle(client: AsyncClient):
    eng = await _create_engagement(client, "Compliance Test")
    eng_id = eng["id"]

    # Create schedule
    r = await client.post(
        "/api/v1/compliance/schedules",
        json={
            "engagement_id": eng_id,
            "framework": "PCI-DSS",
            "frequency": "quarterly",
        },
    )
    assert r.status_code == 201
    sched = r.json()
    assert sched["framework"] == "PCI-DSS"
    assert sched["status"] == "on_track"

    # List
    r = await client.get("/api/v1/compliance/schedules")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # Get
    r = await client.get(f"/api/v1/compliance/schedules/{sched['id']}")
    assert r.status_code == 200

    # Update
    r = await client.put(
        f"/api/v1/compliance/schedules/{sched['id']}",
        json={
            "engagement_id": eng_id,
            "framework": "HIPAA",
            "frequency": "monthly",
        },
    )
    assert r.status_code == 200
    assert r.json()["framework"] == "HIPAA"

    # Delete
    r = await client.delete(f"/api/v1/compliance/schedules/{sched['id']}")
    assert r.status_code == 200


# ── Admin Health ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_admin_health(client: AsyncClient):
    r = await client.get("/api/v1/admin/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "healthy"
    assert "uptime_seconds" in body
    assert "scanner_engines" in body


# ── Dashboard after data ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_dashboard_reflects_data(client: AsyncClient):
    eng = await _create_engagement(client, "Dash Test")
    eng_id = eng["id"]

    await client.post(
        "/api/v1/scans",
        json={"engagement_id": eng_id, "targets": ["http://app"]},
    )

    r = await client.get("/api/v1/dashboard/summary")
    assert r.status_code == 200
    body = r.json()
    # Engagement was moved to in_progress by scan creation
    assert body["active_engagements"] == 1
