"""
api/test_api.py – FastAPI endpoint tests for Threat Intelligence Agent.

Uses httpx.AsyncClient with ASGITransport — no real network calls.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
import httpx
from httpx import ASGITransport


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="module")
async def client(api_app):
    transport = ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as c:
        yield c


# ── Security header checks ────────────────────────────────────────────────────

class TestSecurityHeaders:
    @pytest.mark.asyncio
    async def test_x_content_type_options(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/dashboard/intel")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    @pytest.mark.asyncio
    async def test_x_frame_options(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/dashboard/intel")
        assert resp.headers.get("x-frame-options") == "DENY"

    @pytest.mark.asyncio
    async def test_cache_control_no_store(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/dashboard/intel")
        assert "no-store" in resp.headers.get("cache-control", "")

    @pytest.mark.asyncio
    async def test_content_security_policy_present(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/dashboard/intel")
        assert "content-security-policy" in resp.headers


# ── Health endpoints ──────────────────────────────────────────────────────────

class TestHealthEndpoints:
    @pytest.mark.asyncio
    async def test_admin_health_200(self, client: httpx.AsyncClient):
        resp = await client.get("/admin/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_health_response_structure(self, client: httpx.AsyncClient):
        resp = await client.get("/admin/health")
        data = resp.json()
        assert "status" in data

    @pytest.mark.asyncio
    async def test_admin_config_redacts_secrets(self, client: httpx.AsyncClient):
        resp = await client.get("/admin/config")
        assert resp.status_code == 200
        text = resp.text.lower()
        assert "api_key" not in text or "redacted" in text or "***" in text

    @pytest.mark.asyncio
    async def test_admin_statistics_200(self, client: httpx.AsyncClient):
        resp = await client.get("/admin/statistics")
        assert resp.status_code == 200


# ── Dashboard ────────────────────────────────────────────────────────────────

class TestDashboard:
    @pytest.mark.asyncio
    async def test_dashboard_intel_200(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/dashboard/intel")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_dashboard_response_has_metrics(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/dashboard/intel")
        data = resp.json()
        assert isinstance(data, dict)
        assert len(data) > 0


# ── IOC endpoints ─────────────────────────────────────────────────────────────

class TestIOCEndpoints:
    @pytest.mark.asyncio
    async def test_list_iocs_200(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/iocs")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_iocs_paginated(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/iocs?page=1&page_size=5")
        assert resp.status_code == 200
        data = resp.json()
        items = data.get("items", data.get("data", data if isinstance(data, list) else []))
        assert isinstance(items, list)

    @pytest.mark.asyncio
    async def test_get_ioc_not_found_404(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/iocs/nonexistent-id-xyz")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_ioc_export_post(self, client: httpx.AsyncClient):
        resp = await client.post(
            "/api/v1/iocs/export",
            json={"format": "csv", "tlp_filter": ["GREEN", "WHITE"]},
        )
        assert resp.status_code in (200, 202)

    @pytest.mark.asyncio
    async def test_list_iocs_filter_by_type(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/iocs?ioc_type=ip")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_ioc_invalid_id_format(self, client: httpx.AsyncClient):
        """Malformed IDs (path traversal attempts) must be rejected."""
        resp = await client.get("/api/v1/iocs/../admin/config")
        assert resp.status_code in (400, 404, 422)


# ── Briefs endpoints ──────────────────────────────────────────────────────────

class TestBriefEndpoints:
    @pytest.mark.asyncio
    async def test_list_briefs_200(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/briefs")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_brief_not_found_404(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/briefs/no-such-brief")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_briefs_filter_by_level(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/briefs?level=strategic")
        assert resp.status_code == 200


# ── Actor endpoints ───────────────────────────────────────────────────────────

class TestActorEndpoints:
    @pytest.mark.asyncio
    async def test_list_actors_200(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/actors")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_actor_not_found_404(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/actors/no-such-actor")
        assert resp.status_code == 404


# ── Feed endpoints ────────────────────────────────────────────────────────────

class TestFeedEndpoints:
    @pytest.mark.asyncio
    async def test_list_feeds_200(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/feeds")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_create_feed(self, client: httpx.AsyncClient):
        payload = {
            "name": "test-feed",
            "url": "https://test.example.com/feed",
            "source_type": "osint",
            "tlp": "GREEN",
            "enabled": True,
        }
        resp = await client.post("/api/v1/feeds", json=payload)
        assert resp.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_create_feed_missing_name_422(self, client: httpx.AsyncClient):
        resp = await client.post("/api/v1/feeds", json={"url": "https://test.com"})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_delete_feed_not_found_404(self, client: httpx.AsyncClient):
        resp = await client.delete("/api/v1/feeds/nonexistent-feed-id")
        assert resp.status_code == 404


# ── Processing ────────────────────────────────────────────────────────────────

class TestProcessingEndpoint:
    @pytest.mark.asyncio
    async def test_trigger_pipeline_accepted(self, client: httpx.AsyncClient):
        resp = await client.post("/api/v1/process", json={})
        assert resp.status_code in (200, 202)


# ── Input validation / OWASP ─────────────────────────────────────────────────

class TestInputValidation:
    @pytest.mark.asyncio
    async def test_sql_injection_in_query_param_safe(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/iocs?search=' OR '1'='1")
        assert resp.status_code in (200, 400, 422)
        # Must not return 500 (server error)
        assert resp.status_code != 500

    @pytest.mark.asyncio
    async def test_xss_in_search_param_safe(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/iocs?search=<script>alert(1)</script>")
        assert resp.status_code in (200, 400, 422)
        assert resp.status_code != 500

    @pytest.mark.asyncio
    async def test_oversized_page_size_clamped(self, client: httpx.AsyncClient):
        resp = await client.get("/api/v1/iocs?page_size=99999")
        assert resp.status_code in (200, 400, 422)
