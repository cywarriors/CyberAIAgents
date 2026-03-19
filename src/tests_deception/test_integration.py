"""Integration tests for the full Deception Honeypot Agent pipeline."""
from __future__ import annotations

import pytest

from .mocks import make_decoy, make_exploit_interaction, make_scan_interaction


def _run_pipeline(state: dict) -> dict:
    from deception_honeypot_agent.graph import get_compiled_graph

    get_compiled_graph.cache_clear()
    graph = get_compiled_graph()
    return graph.invoke(state)


class TestPipelineIntegration:
    def test_empty_state_produces_decoys(self):
        """Pipeline with no input deploys decoys from templates."""
        result = _run_pipeline({})
        assert isinstance(result.get("decoy_inventory"), list)
        assert len(result["decoy_inventory"]) > 0

    def test_empty_state_places_honey_creds(self):
        result = _run_pipeline({})
        creds = result.get("honey_credentials", [])
        assert len(creds) > 0
        for c in creds:
            assert c.get("is_synthetic") is True

    def test_no_interactions_produces_no_alerts(self):
        result = _run_pipeline({})
        assert result.get("alerts") == [] or result.get("alerts") is None

    def test_exploit_interaction_produces_critical_alert(self):
        decoy = make_decoy()
        interaction = make_exploit_interaction(decoy_id=decoy["decoy_id"])
        result = _run_pipeline({
            "decoy_inventory": [decoy],
            "interactions": [interaction],
        })
        alerts = result.get("alerts", [])
        assert any(a["severity"] == "critical" for a in alerts)

    def test_scan_interaction_produces_medium_alert(self):
        decoy = make_decoy()
        interaction = make_scan_interaction(decoy_id=decoy["decoy_id"])
        result = _run_pipeline({
            "decoy_inventory": [decoy],
            "interactions": [interaction],
        })
        alerts = result.get("alerts", [])
        assert any(a["severity"] == "medium" for a in alerts)

    def test_multiple_interactions_produce_multiple_alerts(self):
        decoy = make_decoy()
        interactions = [
            make_exploit_interaction(decoy_id=decoy["decoy_id"]),
            make_scan_interaction(decoy_id=decoy["decoy_id"]),
        ]
        result = _run_pipeline({
            "decoy_inventory": [decoy],
            "interactions": interactions,
        })
        assert len(result.get("alerts", [])) >= 2

    def test_attacker_profile_created_for_source_ip(self):
        decoy = make_decoy()
        interaction = make_scan_interaction(source_ip="192.168.66.1", decoy_id=decoy["decoy_id"])
        result = _run_pipeline({
            "decoy_inventory": [decoy],
            "interactions": [interaction],
        })
        profiles = result.get("attacker_profiles", [])
        ips = {p["source_ip"] for p in profiles}
        assert "192.168.66.1" in ips

    def test_coverage_assessment_present_in_result(self):
        result = _run_pipeline({})
        coverage = result.get("coverage_assessment", {})
        assert "coverage_percent" in coverage

    def test_rotation_actions_present_in_result(self):
        result = _run_pipeline({})
        assert "rotation_actions" in result

    def test_ttp_mappings_present_for_exploit(self):
        decoy = make_decoy()
        interaction = make_exploit_interaction(decoy_id=decoy["decoy_id"])
        result = _run_pipeline({
            "decoy_inventory": [decoy],
            "interactions": [interaction],
        })
        assert len(result.get("ttp_mappings", [])) > 0

    def test_canary_tokens_never_contain_real_passwords(self):
        result = _run_pipeline({})
        for cred in result.get("honey_credentials", []):
            pw = cred.get("password_hash", "")
            # Must contain FAKEHASH — never a real bcrypt hash
            assert "FAKEHASH" in pw, f"Potential real credential detected: {pw[:20]}"
