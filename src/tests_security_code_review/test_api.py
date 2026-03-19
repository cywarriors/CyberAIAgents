"""API tests for Security Code Review Agent."""
from __future__ import annotations
import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
async def client(api_app):
    async with AsyncClient(
        transport=ASGITransport(app=api_app),
        base_url="http://localhost",
    ) as ac:
        yield ac


class TestSecurityHeaders:
    @pytest.mark.anyio
    async def test_x_content_type_options(self, client):
        r = await client.get("/admin/health")
        assert r.headers.get("x-content-type-options") == "nosniff"

    @pytest.mark.anyio
    async def test_x_frame_options(self, client):
        r = await client.get("/admin/health")
        assert r.headers.get("x-frame-options") == "DENY"

    @pytest.mark.anyio
    async def test_cache_control(self, client):
        r = await client.get("/admin/health")
        assert r.headers.get("cache-control") == "no-store"

    @pytest.mark.anyio
    async def test_csp_header(self, client):
        r = await client.get("/admin/health")
        csp = r.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp


class TestAdminRoutes:
    @pytest.mark.anyio
    async def test_health_ok(self, client):
        r = await client.get("/admin/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

    @pytest.mark.anyio
    async def test_config_returns_dict(self, client):
        r = await client.get("/admin/config")
        assert r.status_code == 200
        data = r.json()
        assert "vcs_platform" in data

    @pytest.mark.anyio
    async def test_statistics_ok(self, client):
        r = await client.get("/admin/statistics")
        assert r.status_code == 200
        data = r.json()
        assert "sast_findings_count" in data

    @pytest.mark.anyio
    async def test_healthz(self, client):
        r = await client.get("/healthz")
        assert r.status_code == 200


class TestFindingsRoutes:
    @pytest.mark.anyio
    async def test_list_findings_empty(self, client):
        r = await client.get("/api/v1/findings")
        assert r.status_code == 200
        data = r.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    @pytest.mark.anyio
    async def test_get_finding_not_found(self, client):
        r = await client.get("/api/v1/findings/nonexistent-id")
        assert r.status_code == 404

    @pytest.mark.anyio
    async def test_filter_by_severity(self, client):
        r = await client.get("/api/v1/findings?severity=critical")
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_filter_by_type(self, client):
        r = await client.get("/api/v1/findings?finding_type=sast")
        assert r.status_code == 200


class TestSBOMRoutes:
    @pytest.mark.anyio
    async def test_list_sboms_ok(self, client):
        r = await client.get("/api/v1/sbom")
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_get_sbom_not_found(self, client):
        r = await client.get("/api/v1/sbom/nonexistent-id")
        assert r.status_code == 404


class TestPolicyRoutes:
    @pytest.mark.anyio
    async def test_list_verdicts_ok(self, client):
        r = await client.get("/api/v1/policy/verdicts")
        assert r.status_code == 200


class TestScansRoutes:
    @pytest.mark.anyio
    async def test_list_scans_ok(self, client):
        r = await client.get("/api/v1/scans")
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_trigger_scan_accepted(self, client):
        r = await client.post("/api/v1/scans", json={})
        assert r.status_code in (200, 201, 202, 422)


class TestDashboardRoutes:
    @pytest.mark.anyio
    async def test_dashboard_ok(self, client):
        r = await client.get("/api/v1/dashboard/security")
        assert r.status_code == 200
        assert isinstance(r.json(), dict)
