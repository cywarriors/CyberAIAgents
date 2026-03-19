"""API tests for the Deception Honeypot Agent BFF."""
from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
def _app():
    from deception_honeypot_agent.api.app import app
    return app


@pytest.fixture
async def client(_app):
    async with AsyncClient(
        transport=ASGITransport(app=_app),
        base_url="http://localhost",
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
class TestSecurityHeaders:
    async def test_x_content_type_options(self, client):
        r = await client.get("/healthz")
        assert r.headers.get("x-content-type-options") == "nosniff"

    async def test_x_frame_options(self, client):
        r = await client.get("/healthz")
        assert r.headers.get("x-frame-options") == "DENY"

    async def test_cache_control(self, client):
        r = await client.get("/healthz")
        assert r.headers.get("cache-control") == "no-store"

    async def test_csp_header_present(self, client):
        r = await client.get("/healthz")
        assert "content-security-policy" in r.headers


# ---------------------------------------------------------------------------
# Healthz
# ---------------------------------------------------------------------------
class TestHealthz:
    async def test_healthz_returns_200(self, client):
        r = await client.get("/healthz")
        assert r.status_code == 200

    async def test_healthz_response_body(self, client):
        r = await client.get("/healthz")
        assert r.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------
class TestAdmin:
    async def test_health_ok(self, client):
        r = await client.get("/admin/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    async def test_config_returns_ports(self, client):
        r = await client.get("/admin/config")
        assert r.status_code == 200
        data = r.json()
        assert "api_port" in data
        assert "max_decoys" in data

    async def test_statistics_returns_counts(self, client):
        r = await client.get("/admin/statistics")
        assert r.status_code == 200
        data = r.json()
        assert "decoy_count" in data
        assert "interaction_count" in data
        assert "alert_count" in data


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
class TestDashboard:
    async def test_deception_dashboard_ok(self, client):
        r = await client.get("/api/v1/dashboard/deception")
        assert r.status_code == 200

    async def test_deception_dashboard_fields(self, client):
        r = await client.get("/api/v1/dashboard/deception")
        data = r.json()
        assert "summary" in data
        assert "coverage" in data
        assert "recent_alerts" in data
        assert "recent_interactions" in data


# ---------------------------------------------------------------------------
# Decoys
# ---------------------------------------------------------------------------
class TestDecoys:
    async def test_list_decoys_empty(self, client):
        r = await client.get("/api/v1/decoys")
        assert r.status_code == 200
        assert r.json()["items"] == []

    async def test_get_decoy_not_found(self, client):
        r = await client.get("/api/v1/decoys/nonexistent-id")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Interactions
# ---------------------------------------------------------------------------
class TestInteractions:
    async def test_list_interactions_empty(self, client):
        r = await client.get("/api/v1/interactions")
        assert r.status_code == 200
        data = r.json()
        assert data["items"] == []
        assert data["total"] == 0

    async def test_pagination_params_accepted(self, client):
        r = await client.get("/api/v1/interactions?limit=10&offset=0")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
class TestAlerts:
    async def test_list_alerts_empty(self, client):
        r = await client.get("/api/v1/alerts")
        assert r.status_code == 200
        assert r.json()["items"] == []

    async def test_get_alert_not_found(self, client):
        r = await client.get("/api/v1/alerts/nonexistent-alert-id")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------
class TestCoverage:
    async def test_coverage_empty_state(self, client):
        r = await client.get("/api/v1/coverage")
        assert r.status_code == 200
        data = r.json()
        assert "coverage_percent" in data
        assert data["coverage_percent"] == 0.0


# ---------------------------------------------------------------------------
# Attacker Profiles
# ---------------------------------------------------------------------------
class TestAttackerProfiles:
    async def test_list_profiles_empty(self, client):
        r = await client.get("/api/v1/attacker-profiles")
        assert r.status_code == 200
        assert r.json()["items"] == []


# ---------------------------------------------------------------------------
# Pipeline trigger
# ---------------------------------------------------------------------------
class TestPipeline:
    async def test_process_accepted(self, client):
        r = await client.post("/api/v1/process", json={})
        assert r.status_code == 202
        assert r.json()["status"] == "accepted"
