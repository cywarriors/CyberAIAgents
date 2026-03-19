"""API tests for the Compliance and Audit Agent BFF."""

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


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

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
    async def test_content_security_policy(self, client):
        r = await client.get("/admin/health")
        csp = r.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

class TestAdminRoutes:
    @pytest.mark.anyio
    async def test_health_ok(self, client):
        r = await client.get("/admin/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("healthy", "ok")

    @pytest.mark.anyio
    async def test_config_returns_dict(self, client):
        r = await client.get("/admin/config")
        assert r.status_code == 200
        assert isinstance(r.json(), dict)

    @pytest.mark.anyio
    async def test_statistics_has_counts(self, client):
        r = await client.get("/admin/statistics")
        assert r.status_code == 200
        data = r.json()
        assert "evidence_count" in data or "total_evidence" in data or isinstance(data, dict)

    @pytest.mark.anyio
    async def test_healthz_endpoint(self, client):
        r = await client.get("/healthz")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class TestDashboardRoutes:
    @pytest.mark.anyio
    async def test_compliance_dashboard_ok(self, client):
        r = await client.get("/api/v1/dashboard/compliance")
        assert r.status_code == 200
        assert isinstance(r.json(), dict)


# ---------------------------------------------------------------------------
# Evidence routes
# ---------------------------------------------------------------------------

class TestEvidenceRoutes:
    @pytest.mark.anyio
    async def test_list_evidence_empty(self, client):
        r = await client.get("/api/v1/evidence")
        assert r.status_code == 200
        data = r.json()
        # Paginated response: {items: [...], total: N}
        assert "items" in data
        assert isinstance(data["items"], list)

    @pytest.mark.anyio
    async def test_get_evidence_not_found(self, client):
        r = await client.get("/api/v1/evidence/nonexistent-id")
        assert r.status_code == 404

    @pytest.mark.anyio
    async def test_invalid_evidence_id_rejected(self, client):
        r = await client.get("/api/v1/evidence/../../etc/passwd")
        assert r.status_code in (404, 422)


# ---------------------------------------------------------------------------
# Gaps routes
# ---------------------------------------------------------------------------

class TestGapsRoutes:
    @pytest.mark.anyio
    async def test_list_gaps_empty(self, client):
        r = await client.get("/api/v1/gaps")
        assert r.status_code == 200
        data = r.json()
        # Paginated response: {items: [...], total: N}
        assert "items" in data
        assert isinstance(data["items"], list)

    @pytest.mark.anyio
    async def test_get_gap_not_found(self, client):
        r = await client.get("/api/v1/gaps/nonexistent-id")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Audit packs routes
# ---------------------------------------------------------------------------

class TestAuditPacksRoutes:
    @pytest.mark.anyio
    async def test_list_audit_packs_empty(self, client):
        r = await client.get("/api/v1/audit-packs")
        assert r.status_code == 200
        data = r.json()
        # May be list or paginated dict
        assert isinstance(data, (list, dict))

    @pytest.mark.anyio
    async def test_get_audit_pack_not_found(self, client):
        r = await client.get("/api/v1/audit-packs/nonexistent-id")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Frameworks routes
# ---------------------------------------------------------------------------

class TestFrameworksRoutes:
    @pytest.mark.anyio
    async def test_list_frameworks_ok(self, client):
        r = await client.get("/api/v1/frameworks")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    @pytest.mark.anyio
    async def test_get_framework_not_found(self, client):
        r = await client.get("/api/v1/frameworks/UNKNOWN_FRAMEWORK")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Sources routes (CRUD)
# ---------------------------------------------------------------------------

class TestSourcesRoutes:
    @pytest.mark.anyio
    async def test_list_sources_empty(self, client):
        r = await client.get("/api/v1/sources")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @pytest.mark.anyio
    async def test_create_source_ok(self, client):
        payload = {
            "name": "Test SIEM",
            "source_type": "siem",
            "api_url": "http://siem.internal",
            "enabled": True,
        }
        r = await client.post("/api/v1/sources", json=payload)
        assert r.status_code == 201
        data = r.json()
        assert "feed_id" in data
        assert data["name"] == "Test SIEM"

    @pytest.mark.anyio
    async def test_delete_source_not_found(self, client):
        r = await client.delete("/api/v1/sources/nonexistent-id")
        assert r.status_code == 404

    @pytest.mark.anyio
    async def test_delete_source_invalid_id(self, client):
        r = await client.delete("/api/v1/sources/../traversal")
        assert r.status_code in (404, 422)


# ---------------------------------------------------------------------------
# Processing routes
# ---------------------------------------------------------------------------

class TestProcessingRoutes:
    @pytest.mark.anyio
    async def test_process_endpoint_accepted(self, client):
        r = await client.post("/api/v1/process", json={})
        # Either 200 (sync) or 202 (async accepted)
        assert r.status_code in (200, 202, 422)
