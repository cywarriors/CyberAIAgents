"""Integration tests – run full LangGraph pipeline with production-like scenarios."""

from __future__ import annotations

from typing import Any

import pytest

from identity_access_agent.graph import get_compiled_graph
from tests_identity.mocks.scenarios import SCENARIOS, IdentityScenario

_RISK_LEVELS_ORDERED = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_risk_level(risk_scores: list[dict]) -> str:
    """Return the highest risk level from a list of risk scores."""
    if not risk_scores:
        return "low"
    return max(
        (s.get("risk_level", "low") for s in risk_scores),
        key=lambda x: _RISK_LEVELS_ORDERED.get(x, 0),
    )


class TestFullPipeline:
    """End-to-end pipeline tests using named attack scenarios."""

    @pytest.fixture(autouse=True)
    def _clear_graph_cache(self):
        """Ensure a fresh graph for each test."""
        get_compiled_graph.cache_clear()
        yield
        get_compiled_graph.cache_clear()

    @pytest.mark.parametrize(
        "scenario",
        SCENARIOS,
        ids=[s.name for s in SCENARIOS],
    )
    def test_scenario(self, scenario: IdentityScenario):
        """Run a scenario through the full pipeline and validate expectations."""
        graph = get_compiled_graph()
        result = graph.invoke({
            "raw_auth_events": scenario.auth_events,
            "raw_role_changes": scenario.role_changes,
        })

        # Verify pipeline produced expected state keys
        assert "batch_id" in result
        assert "risk_scores" in result
        assert "alerts" in result
        assert "recommendations" in result

        # Verify anomaly types
        if scenario.expected_anomaly_types:
            anomaly_types = {a["anomaly_type"] for a in result.get("session_anomalies", [])}
            for expected in scenario.expected_anomaly_types:
                assert expected in anomaly_types, (
                    f"Scenario '{scenario.name}': expected anomaly '{expected}' "
                    f"not found in {anomaly_types}"
                )

        # Verify takeover signals
        if scenario.expected_takeover_signals:
            signal_types = {s["signal_type"] for s in result.get("takeover_signals", [])}
            for expected in scenario.expected_takeover_signals:
                assert expected in signal_types, (
                    f"Scenario '{scenario.name}': expected signal '{expected}' "
                    f"not found in {signal_types}"
                )

        # Verify privilege alerts
        if scenario.expected_privilege_alerts:
            alert_types = {a["alert_type"] for a in result.get("privilege_alerts", [])}
            for expected in scenario.expected_privilege_alerts:
                assert expected in alert_types, (
                    f"Scenario '{scenario.name}': expected privilege alert '{expected}' "
                    f"not found in {alert_types}"
                )

        # Verify SoD violations
        assert len(result.get("sod_violations", [])) >= scenario.expected_sod_violations, (
            f"Scenario '{scenario.name}': expected >= {scenario.expected_sod_violations} "
            f"SoD violations, got {len(result.get('sod_violations', []))}"
        )

        # Verify minimum risk level
        risk_scores = result.get("risk_scores", [])
        if risk_scores:
            actual_max = _max_risk_level(risk_scores)
            assert _RISK_LEVELS_ORDERED.get(actual_max, 0) >= _RISK_LEVELS_ORDERED.get(
                scenario.min_expected_risk_level, 0
            ), (
                f"Scenario '{scenario.name}': expected min risk '{scenario.min_expected_risk_level}', "
                f"got '{actual_max}'"
            )

        # Verify alert generation
        if scenario.should_generate_alert:
            assert len(result.get("alerts", [])) >= 1, (
                f"Scenario '{scenario.name}': expected alert but none generated"
            )


class TestPipelineStateIntegrity:
    """Verify the pipeline maintains correct state structure."""

    @pytest.fixture(autouse=True)
    def _clear_cache(self):
        get_compiled_graph.cache_clear()
        yield
        get_compiled_graph.cache_clear()

    def test_all_state_keys_present(self):
        """Pipeline output should contain all IdentityRiskState fields."""
        from tests_identity.mocks.generators import generate_mixed_auth_batch, generate_mixed_role_batch
        graph = get_compiled_graph()
        result = graph.invoke({
            "raw_auth_events": generate_mixed_auth_batch(),
            "raw_role_changes": generate_mixed_role_batch(),
        })
        expected_keys = [
            "batch_id", "raw_auth_events", "raw_role_changes",
            "session_profiles", "session_anomalies",
            "privilege_alerts", "sod_violations",
            "takeover_signals", "risk_scores",
            "recommendations", "alerts", "feedback_queue",
        ]
        for key in expected_keys:
            assert key in result, f"Missing state key: {key}"

    def test_batch_id_consistent(self):
        from tests_identity.mocks.generators import generate_normal_auth_events
        graph = get_compiled_graph()
        result = graph.invoke({
            "raw_auth_events": generate_normal_auth_events(5),
            "raw_role_changes": [],
        })
        batch_id = result["batch_id"]
        assert batch_id.startswith("iam-")
        for evt in result["raw_auth_events"]:
            assert evt["_batch_id"] == batch_id

    def test_risk_scores_for_all_users(self):
        """Every user in session profiles should have a risk score."""
        from tests_identity.mocks.generators import generate_mixed_auth_batch
        graph = get_compiled_graph()
        result = graph.invoke({
            "raw_auth_events": generate_mixed_auth_batch(),
            "raw_role_changes": [],
        })
        profile_users = {p["user_id"] for p in result["session_profiles"]}
        scored_users = {s["user_id"] for s in result["risk_scores"]}
        assert profile_users.issubset(scored_users)

    def test_recommendation_for_each_scored_user(self):
        """Every scored user should get a recommendation."""
        from tests_identity.mocks.generators import generate_mixed_auth_batch
        graph = get_compiled_graph()
        result = graph.invoke({
            "raw_auth_events": generate_mixed_auth_batch(),
            "raw_role_changes": [],
        })
        scored_users = {s["user_id"] for s in result["risk_scores"]}
        rec_users = {r["user_id"] for r in result["recommendations"]}
        assert scored_users.issubset(rec_users)


class TestMixedScenarioPipeline:
    """Run mixed-batch scenarios through the full pipeline."""

    @pytest.fixture(autouse=True)
    def _clear_cache(self):
        get_compiled_graph.cache_clear()
        yield
        get_compiled_graph.cache_clear()

    def test_combined_attack_batch(self):
        """Mixed batch with multiple attack types creates multiple alert types."""
        from tests_identity.mocks.generators import generate_mixed_auth_batch, generate_mixed_role_batch
        graph = get_compiled_graph()
        result = graph.invoke({
            "raw_auth_events": generate_mixed_auth_batch(),
            "raw_role_changes": generate_mixed_role_batch(),
        })
        # Should detect session anomalies
        assert len(result["session_anomalies"]) >= 1
        # Should detect privilege alerts
        assert len(result["privilege_alerts"]) >= 1
        # Should detect SoD violations
        assert len(result["sod_violations"]) >= 1
        # Should create alerts for high/critical risk users
        assert len(result["alerts"]) >= 1

    def test_empty_pipeline(self):
        """Empty input should produce empty results."""
        graph = get_compiled_graph()
        result = graph.invoke({"raw_auth_events": [], "raw_role_changes": []})
        assert result["risk_scores"] == []
        assert result["alerts"] == []
        assert result["session_anomalies"] == []
