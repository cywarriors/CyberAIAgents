"""Integration tests for the FastAPI application."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from identity_access_agent.api import dependencies as deps


@pytest.fixture(autouse=True)
def _reset_store():
    """Reset the in-memory store before each test."""
    deps._store_instance = None
    yield
    deps._store_instance = None


@pytest.fixture()
def client():
    """TestClient that bypasses TrustedHost middleware."""
    from identity_access_agent.api.app import app
    return TestClient(app, headers={"host": "localhost"})


class TestRootEndpoints:
    def test_root(self, client: TestClient):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert "Identity" in data["message"]

    def test_api_root(self, client: TestClient):
        resp = client.get("/api/v1")
        assert resp.status_code == 200
        assert "endpoints" in resp.json()


class TestDashboard:
    def test_empty_dashboard(self, client: TestClient):
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_events_processed"] == 0


class TestAlerts:
    def test_list_alerts_empty(self, client: TestClient):
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_alert_not_found(self, client: TestClient):
        resp = client.get("/api/v1/alerts/nonexistent")
        assert resp.status_code == 404

    def test_alert_lifecycle(self, client: TestClient):
        """Create alert via store, then feedback and close."""
        store = deps.get_store()
        store.alerts["A1"] = {
            "alert_id": "A1", "user_id": "U1", "username": "test",
            "severity": "high", "title": "Test", "description": "Test alert",
            "risk_score": 70.0, "indicators": [], "recommended_control": "step_up_mfa",
            "status": "open", "created_at": "2025-01-15T10:00:00Z", "ticket_id": "IAM-TEST",
        }

        # Get alert
        resp = client.get("/api/v1/alerts/A1")
        assert resp.status_code == 200
        assert resp.json()["alert_id"] == "A1"

        # Submit feedback
        resp = client.post("/api/v1/alerts/A1/feedback", json={
            "analyst_id": "SOC-01",
            "verdict": "true_positive",
            "notes": "Confirmed attack",
        })
        assert resp.status_code == 200
        assert store.alerts["A1"]["status"] == "reviewed"

        # Close alert
        resp = client.post("/api/v1/alerts/A1/close")
        assert resp.status_code == 200
        assert store.alerts["A1"]["status"] == "closed"

    def test_feedback_invalid_verdict(self, client: TestClient):
        store = deps.get_store()
        store.alerts["A1"] = {"alert_id": "A1", "status": "open"}
        resp = client.post("/api/v1/alerts/A1/feedback", json={
            "analyst_id": "SOC-01",
            "verdict": "invalid_verdict",
        })
        assert resp.status_code == 422


class TestRiskScores:
    def test_list_empty(self, client: TestClient):
        resp = client.get("/api/v1/risk-scores")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_by_user(self, client: TestClient):
        store = deps.get_store()
        store.risk_scores["U1"] = {
            "user_id": "U1", "username": "alice", "risk_score": 75.0,
            "risk_level": "high", "indicators": [], "components": {},
            "explanation": "test", "confidence": 0.8,
        }
        resp = client.get("/api/v1/risk-scores/U1")
        assert resp.status_code == 200
        assert resp.json()["risk_score"] == 75.0

    def test_filter_by_level(self, client: TestClient):
        store = deps.get_store()
        store.risk_scores["U1"] = {"user_id": "U1", "risk_level": "high", "risk_score": 70.0}
        store.risk_scores["U2"] = {"user_id": "U2", "risk_level": "low", "risk_score": 10.0}
        resp = client.get("/api/v1/risk-scores?risk_level=high")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["user_id"] == "U1"


class TestUsers:
    def test_list_empty(self, client: TestClient):
        resp = client.get("/api/v1/users")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_user(self, client: TestClient):
        store = deps.get_store()
        store.users["U1"] = {
            "user_id": "U1", "username": "alice", "risk_score": 50.0,
            "risk_level": "medium",
        }
        resp = client.get("/api/v1/users/U1")
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"


class TestSoDViolations:
    def test_list_empty(self, client: TestClient):
        resp = client.get("/api/v1/sod-violations")
        assert resp.status_code == 200
        assert resp.json() == []


class TestRecommendations:
    def test_list_empty(self, client: TestClient):
        resp = client.get("/api/v1/recommendations")
        assert resp.status_code == 200
        assert resp.json() == []


class TestProcessing:
    def test_empty_body_rejected(self, client: TestClient):
        resp = client.post("/api/v1/process", json={"auth_events": [], "role_changes": []})
        assert resp.status_code == 400

    def test_process_auth_events(self, client: TestClient):
        from tests_identity.mocks.generators import generate_brute_force_events
        events = generate_brute_force_events()
        resp = client.post("/api/v1/process", json={
            "auth_events": events,
            "role_changes": [],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_events_processed"] == len(events)
        assert data["risk_scores_computed"] >= 1
        assert data["alerts_created"] >= 1

    def test_process_persists_to_store(self, client: TestClient):
        from tests_identity.mocks.generators import generate_brute_force_events
        events = generate_brute_force_events()
        client.post("/api/v1/process", json={"auth_events": events, "role_changes": []})
        store = deps.get_store()
        assert len(store.risk_scores) >= 1
        assert len(store.alerts) >= 1
        assert len(store.users) >= 1

    def test_process_role_changes(self, client: TestClient):
        from tests_identity.mocks.generators import generate_self_escalation_role_changes
        roles = generate_self_escalation_role_changes()
        resp = client.post("/api/v1/process", json={
            "auth_events": [{"user_id": "USR-001", "username": "test", "outcome": "success"}],
            "role_changes": roles,
        })
        assert resp.status_code == 200


class TestAdmin:
    def test_health(self, client: TestClient):
        resp = client.get("/api/v1/admin/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_config(self, client: TestClient):
        resp = client.get("/api/v1/admin/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_threshold_critical" in data
        assert "agent_env" in data

    def test_statistics(self, client: TestClient):
        resp = client.get("/api/v1/admin/statistics")
        assert resp.status_code == 200
        assert "total_risk_scores" in resp.json()

    def test_audit_log(self, client: TestClient):
        resp = client.get("/api/v1/admin/audit-log")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestSecurityHeaders:
    def test_security_headers_present(self, client: TestClient):
        resp = client.get("/")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Cache-Control") == "no-store"
