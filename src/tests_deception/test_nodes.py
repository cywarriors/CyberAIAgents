"""Unit tests for all Deception Honeypot Agent nodes."""
from __future__ import annotations

import pytest

from .mocks import (
    make_classified_interaction,
    make_credential_interaction,
    make_decoy,
    make_exploit_interaction,
    make_interaction,
    make_lateral_interaction,
    make_scan_interaction,
    make_ttp_mapping,
)


# ---------------------------------------------------------------------------
# TestDeployDecoys
# ---------------------------------------------------------------------------
class TestDeployDecoys:
    def test_returns_decoys_list(self, empty_state):
        from deception_honeypot_agent.nodes.deploy_decoys import deploy_decoys

        result = deploy_decoys(empty_state)
        assert "decoy_inventory" in result
        assert isinstance(result["decoy_inventory"], list)

    def test_deploys_multiple_decoy_types(self, empty_state):
        from deception_honeypot_agent.nodes.deploy_decoys import deploy_decoys

        result = deploy_decoys(empty_state)
        types = {d["decoy_type"] for d in result["decoy_inventory"]}
        assert len(types) >= 2

    def test_decoys_have_required_fields(self, empty_state):
        from deception_honeypot_agent.nodes.deploy_decoys import deploy_decoys

        result = deploy_decoys(empty_state)
        for d in result["decoy_inventory"]:
            assert "decoy_id" in d
            assert "decoy_type" in d
            assert "service" in d
            assert "active" in d

    def test_passthrough_when_inventory_exists(self, empty_state):
        from deception_honeypot_agent.nodes.deploy_decoys import deploy_decoys

        existing = [make_decoy()]
        state = {**empty_state, "decoy_inventory": existing}
        result = deploy_decoys(state)
        assert result["decoy_inventory"] is existing or result["decoy_inventory"] == existing

    def test_decoys_are_active_on_deploy(self, empty_state):
        from deception_honeypot_agent.nodes.deploy_decoys import deploy_decoys

        result = deploy_decoys(empty_state)
        for d in result["decoy_inventory"]:
            assert d.get("active") is True

    def test_decoys_start_with_zero_interactions(self, empty_state):
        from deception_honeypot_agent.nodes.deploy_decoys import deploy_decoys

        result = deploy_decoys(empty_state)
        for d in result["decoy_inventory"]:
            assert d.get("interaction_count", 0) == 0


# ---------------------------------------------------------------------------
# TestPlaceHoneyCreds
# ---------------------------------------------------------------------------
class TestPlaceHoneyCreds:
    def test_returns_credentials(self, empty_state):
        from deception_honeypot_agent.nodes.place_honey_creds import place_honey_creds

        result = place_honey_creds(empty_state)
        assert "honey_credentials" in result
        assert len(result["honey_credentials"]) > 0

    def test_returns_canary_tokens(self, empty_state):
        from deception_honeypot_agent.nodes.place_honey_creds import place_honey_creds

        result = place_honey_creds(empty_state)
        assert "canary_tokens" in result
        assert len(result["canary_tokens"]) > 0

    def test_credentials_are_synthetic(self, empty_state):
        """SEC-01: honey credentials must never be real."""
        from deception_honeypot_agent.nodes.place_honey_creds import place_honey_creds

        result = place_honey_creds(empty_state)
        for cred in result["honey_credentials"]:
            assert cred.get("is_synthetic") is True

    def test_password_hash_is_fake(self, empty_state):
        """SEC-01 detail: password hash must contain FAKEHASH sentinel."""
        from deception_honeypot_agent.nodes.place_honey_creds import place_honey_creds

        result = place_honey_creds(empty_state)
        for cred in result["honey_credentials"]:
            assert "FAKEHASH" in cred.get("password_hash", ""), \
                "Real password hashes must not reach honey creds"

    def test_canary_tokens_have_token_value(self, empty_state):
        from deception_honeypot_agent.nodes.place_honey_creds import place_honey_creds

        result = place_honey_creds(empty_state)
        for token in result["canary_tokens"]:
            assert "CANARY-" in token.get("token_value", "")

    def test_passthrough_when_data_exists(self, empty_state):
        from deception_honeypot_agent.nodes.place_honey_creds import place_honey_creds

        existing_creds = [{"cred_id": "x", "is_synthetic": True}]
        existing_tokens = [{"token_id": "y"}]
        state = {**empty_state, "honey_credentials": existing_creds, "canary_tokens": existing_tokens}
        result = place_honey_creds(state)
        assert result["honey_credentials"] == existing_creds


# ---------------------------------------------------------------------------
# TestMonitorInteractions
# ---------------------------------------------------------------------------
class TestMonitorInteractions:
    def test_enriches_interactions_with_decoy_metadata(self, empty_state):
        from deception_honeypot_agent.nodes.monitor_interactions import monitor_interactions

        decoy = make_decoy(decoy_type="honey_db", service="postgresql")
        interaction = make_interaction(decoy_id=decoy["decoy_id"])
        state = {**empty_state, "decoy_inventory": [decoy], "interactions": [interaction]}
        result = monitor_interactions(state)
        enriched = result["interactions"]
        assert len(enriched) == 1
        assert enriched[0].get("decoy_type") == "honey_db"

    def test_handles_empty_interactions(self, empty_state):
        from deception_honeypot_agent.nodes.monitor_interactions import monitor_interactions

        result = monitor_interactions(empty_state)
        assert result["interactions"] == []

    def test_unknown_decoy_id_still_returns_interaction(self, empty_state):
        from deception_honeypot_agent.nodes.monitor_interactions import monitor_interactions

        interaction = make_interaction(decoy_id="nonexistent-id")
        state = {**empty_state, "interactions": [interaction]}
        result = monitor_interactions(state)
        assert len(result["interactions"]) == 1


# ---------------------------------------------------------------------------
# TestClassifyInteraction
# ---------------------------------------------------------------------------
class TestClassifyInteraction:
    def test_exploit_keywords_classified_exploit(self, empty_state):
        from deception_honeypot_agent.nodes.classify_interaction import classify_interaction

        state = {**empty_state, "interactions": [make_exploit_interaction()]}
        result = classify_interaction(state)
        assert result["classified_interactions"][0]["interaction_type"] == "exploit"

    def test_scan_keywords_classified_scan(self, empty_state):
        from deception_honeypot_agent.nodes.classify_interaction import classify_interaction

        state = {**empty_state, "interactions": [make_scan_interaction()]}
        result = classify_interaction(state)
        assert result["classified_interactions"][0]["interaction_type"] == "scan"

    def test_lateral_keywords_classified_lateral(self, empty_state):
        from deception_honeypot_agent.nodes.classify_interaction import classify_interaction

        state = {**empty_state, "interactions": [make_lateral_interaction()]}
        result = classify_interaction(state)
        assert result["classified_interactions"][0]["interaction_type"] == "lateral"

    def test_credential_keywords_classified_credential(self, empty_state):
        from deception_honeypot_agent.nodes.classify_interaction import classify_interaction

        state = {**empty_state, "interactions": [make_credential_interaction()]}
        result = classify_interaction(state)
        assert result["classified_interactions"][0]["interaction_type"] == "credential_use"

    def test_unknown_action_classified_unknown(self, empty_state):
        from deception_honeypot_agent.nodes.classify_interaction import classify_interaction

        state = {**empty_state, "interactions": [make_interaction(action="heartbeat", raw_event="")]}
        result = classify_interaction(state)
        assert result["classified_interactions"][0]["interaction_type"] == "unknown"

    def test_confidence_lower_for_unknown(self, empty_state):
        from deception_honeypot_agent.nodes.classify_interaction import classify_interaction

        state = {**empty_state, "interactions": [make_interaction(raw_event="")]}
        result = classify_interaction(state)
        unknown_item = result["classified_interactions"][0]
        if unknown_item["interaction_type"] == "unknown":
            assert unknown_item["confidence"] < 0.5

    def test_classified_preserves_original_fields(self, empty_state):
        from deception_honeypot_agent.nodes.classify_interaction import classify_interaction

        interaction = make_scan_interaction()
        state = {**empty_state, "interactions": [interaction]}
        result = classify_interaction(state)
        classified = result["classified_interactions"][0]
        assert classified["interaction_id"] == interaction["interaction_id"]
        assert classified["source_ip"] == interaction["source_ip"]


# ---------------------------------------------------------------------------
# TestMapTTPs
# ---------------------------------------------------------------------------
class TestMapTTPs:
    def test_exploit_maps_to_technique(self, empty_state):
        from deception_honeypot_agent.nodes.map_ttps import map_ttps

        c = make_classified_interaction(interaction_type="exploit")
        state = {**empty_state, "classified_interactions": [c]}
        result = map_ttps(state)
        assert len(result["ttp_mappings"]) > 0

    def test_scan_maps_to_discovery_tactic(self, empty_state):
        from deception_honeypot_agent.nodes.map_ttps import map_ttps

        c = make_classified_interaction(interaction_type="scan")
        state = {**empty_state, "classified_interactions": [c]}
        result = map_ttps(state)
        tactics = {m["tactic"].lower() for m in result["ttp_mappings"]}
        assert "discovery" in tactics

    def test_mappings_have_technique_id(self, empty_state):
        from deception_honeypot_agent.nodes.map_ttps import map_ttps

        c = make_classified_interaction(interaction_type="lateral")
        state = {**empty_state, "classified_interactions": [c]}
        result = map_ttps(state)
        for m in result["ttp_mappings"]:
            assert m["technique_id"].startswith("T")

    def test_unknown_type_still_returns_list(self, empty_state):
        from deception_honeypot_agent.nodes.map_ttps import map_ttps

        c = make_classified_interaction(interaction_type="unknown")
        state = {**empty_state, "classified_interactions": [c]}
        result = map_ttps(state)
        assert isinstance(result["ttp_mappings"], list)

    def test_mapping_references_correct_interaction_id(self, empty_state):
        from deception_honeypot_agent.nodes.map_ttps import map_ttps

        c = make_classified_interaction(interaction_type="scan")
        state = {**empty_state, "classified_interactions": [c]}
        result = map_ttps(state)
        for m in result["ttp_mappings"]:
            assert m["interaction_id"] == c["interaction_id"]


# ---------------------------------------------------------------------------
# TestGenerateAlert
# ---------------------------------------------------------------------------
class TestGenerateAlert:
    def test_exploit_produces_critical_alert(self, empty_state):
        from deception_honeypot_agent.nodes.generate_alert import generate_alert

        c = make_classified_interaction(interaction_type="exploit")
        state = {**empty_state, "classified_interactions": [c]}
        result = generate_alert(state)
        assert result["alerts"][0]["severity"] == "critical"

    def test_lateral_produces_critical_alert(self, empty_state):
        from deception_honeypot_agent.nodes.generate_alert import generate_alert

        c = make_classified_interaction(interaction_type="lateral")
        state = {**empty_state, "classified_interactions": [c]}
        result = generate_alert(state)
        assert result["alerts"][0]["severity"] == "critical"

    def test_credential_use_produces_high_alert(self, empty_state):
        from deception_honeypot_agent.nodes.generate_alert import generate_alert

        c = make_classified_interaction(interaction_type="credential_use")
        state = {**empty_state, "classified_interactions": [c]}
        result = generate_alert(state)
        assert result["alerts"][0]["severity"] == "high"

    def test_scan_produces_medium_alert(self, empty_state):
        from deception_honeypot_agent.nodes.generate_alert import generate_alert

        c = make_classified_interaction(interaction_type="scan")
        state = {**empty_state, "classified_interactions": [c]}
        result = generate_alert(state)
        assert result["alerts"][0]["severity"] == "medium"

    def test_alerts_have_required_fields(self, empty_state):
        from deception_honeypot_agent.nodes.generate_alert import generate_alert

        c = make_classified_interaction()
        state = {**empty_state, "classified_interactions": [c]}
        result = generate_alert(state)
        alert = result["alerts"][0]
        for field in ("alert_id", "severity", "interaction_type", "title", "description"):
            assert field in alert

    def test_no_interactions_produces_no_alerts(self, empty_state):
        from deception_honeypot_agent.nodes.generate_alert import generate_alert

        result = generate_alert(empty_state)
        assert result["alerts"] == []

    def test_alert_false_positive_default_false(self, empty_state):
        from deception_honeypot_agent.nodes.generate_alert import generate_alert

        c = make_classified_interaction(interaction_type="probe")
        state = {**empty_state, "classified_interactions": [c]}
        result = generate_alert(state)
        assert result["alerts"][0]["false_positive"] is False


# ---------------------------------------------------------------------------
# TestProfileAttacker
# ---------------------------------------------------------------------------
class TestProfileAttacker:
    def test_groups_by_source_ip(self, empty_state):
        from deception_honeypot_agent.nodes.profile_attacker import profile_attacker

        c1 = make_classified_interaction(source_ip="1.2.3.4")
        c2 = make_classified_interaction(source_ip="1.2.3.4")
        c3 = make_classified_interaction(source_ip="5.6.7.8")
        state = {**empty_state, "classified_interactions": [c1, c2, c3]}
        result = profile_attacker(state)
        assert len(result["attacker_profiles"]) == 2

    def test_profile_has_threat_level(self, empty_state):
        from deception_honeypot_agent.nodes.profile_attacker import profile_attacker

        c = make_classified_interaction(interaction_type="exploit", source_ip="9.9.9.9")
        state = {**empty_state, "classified_interactions": [c]}
        result = profile_attacker(state)
        assert result["attacker_profiles"][0]["threat_level"] == "critical"

    def test_scan_profile_threat_level_low(self, empty_state):
        from deception_honeypot_agent.nodes.profile_attacker import profile_attacker

        c = make_classified_interaction(interaction_type="scan", source_ip="2.2.2.2")
        state = {**empty_state, "classified_interactions": [c]}
        result = profile_attacker(state)
        assert result["attacker_profiles"][0]["threat_level"] == "low"

    def test_dominant_behavior_computed(self, empty_state):
        from deception_honeypot_agent.nodes.profile_attacker import profile_attacker

        interactions = [
            make_classified_interaction(interaction_type="scan", source_ip="3.3.3.3")
            for _ in range(3)
        ] + [make_classified_interaction(interaction_type="probe", source_ip="3.3.3.3")]
        state = {**empty_state, "classified_interactions": interactions}
        result = profile_attacker(state)
        assert result["attacker_profiles"][0]["dominant_behavior"] == "scan"

    def test_empty_interactions_returns_empty_profiles(self, empty_state):
        from deception_honeypot_agent.nodes.profile_attacker import profile_attacker

        result = profile_attacker(empty_state)
        assert result["attacker_profiles"] == []


# ---------------------------------------------------------------------------
# TestAssessCoverage
# ---------------------------------------------------------------------------
class TestAssessCoverage:
    def test_full_coverage_when_all_types_present(self, empty_state):
        from deception_honeypot_agent.nodes.assess_coverage import assess_coverage, _TARGET_DECOY_TYPES

        decoys = [make_decoy(decoy_type=dt) for dt in _TARGET_DECOY_TYPES]
        state = {**empty_state, "decoy_inventory": decoys}
        result = assess_coverage(state)
        assessment = result["coverage_assessment"]
        assert assessment["coverage_percent"] == 100.0
        assert assessment["missing_types"] == []

    def test_partial_coverage_produces_recommendations(self, empty_state):
        from deception_honeypot_agent.nodes.assess_coverage import assess_coverage

        decoys = [make_decoy(decoy_type="fake_server")]
        state = {**empty_state, "decoy_inventory": decoys}
        result = assess_coverage(state)
        assessment = result["coverage_assessment"]
        assert assessment["coverage_percent"] < 100.0
        assert len(assessment["recommendations"]) > 0

    def test_empty_inventory_zero_coverage(self, empty_state):
        from deception_honeypot_agent.nodes.assess_coverage import assess_coverage

        result = assess_coverage(empty_state)
        assessment = result["coverage_assessment"]
        assert assessment["coverage_percent"] == 0.0

    def test_assessment_has_required_fields(self, empty_state):
        from deception_honeypot_agent.nodes.assess_coverage import assess_coverage

        result = assess_coverage(empty_state)
        assessment = result["coverage_assessment"]
        for field in ("total_decoys", "active_decoys", "deployed_types", "missing_types",
                      "coverage_percent", "target_percent", "meets_target", "recommendations"):
            assert field in assessment

    def test_inactive_decoys_excluded_from_coverage(self, empty_state):
        from deception_honeypot_agent.nodes.assess_coverage import assess_coverage

        decoys = [make_decoy(decoy_type="fake_server", active=False)]
        state = {**empty_state, "decoy_inventory": decoys}
        result = assess_coverage(state)
        assessment = result["coverage_assessment"]
        # inactive decoy shouldn't count as deployed
        assert "fake_server" not in assessment["deployed_types"]


# ---------------------------------------------------------------------------
# TestRotateDecoys
# ---------------------------------------------------------------------------
class TestRotateDecoys:
    def test_retires_high_interaction_decoys(self, empty_state):
        from deception_honeypot_agent.nodes.rotate_decoys import rotate_decoys

        burned = make_decoy(interaction_count=150)
        state = {**empty_state, "decoy_inventory": [burned]}
        result = rotate_decoys(state)
        retired = [a for a in result["rotation_actions"] if a["action"] == "retire"]
        assert len(retired) == 1
        assert retired[0]["decoy_id"] == burned["decoy_id"]

    def test_retired_decoy_marked_inactive(self, empty_state):
        from deception_honeypot_agent.nodes.rotate_decoys import rotate_decoys

        burned = make_decoy(interaction_count=200)
        state = {**empty_state, "decoy_inventory": [burned]}
        result = rotate_decoys(state)
        for d in result["decoy_inventory"]:
            if d["decoy_id"] == burned["decoy_id"]:
                assert d["active"] is False

    def test_normal_decoys_not_retired(self, empty_state):
        from deception_honeypot_agent.nodes.rotate_decoys import rotate_decoys

        normal = make_decoy(interaction_count=5)
        state = {**empty_state, "decoy_inventory": [normal]}
        result = rotate_decoys(state)
        retired = [a for a in result["rotation_actions"] if a["action"] == "retire"]
        assert len(retired) == 0

    def test_deploys_for_missing_types(self, empty_state):
        from deception_honeypot_agent.nodes.rotate_decoys import rotate_decoys

        coverage = {"missing_types": ["honey_account"], "recommendations": []}
        state = {**empty_state, "coverage_assessment": coverage}
        result = rotate_decoys(state)
        deployed = [a for a in result["rotation_actions"] if a["action"] == "deploy"]
        assert len(deployed) == 1
        assert deployed[0]["decoy_type"] == "honey_account"

    def test_rotation_actions_have_timestamps(self, empty_state):
        from deception_honeypot_agent.nodes.rotate_decoys import rotate_decoys

        burned = make_decoy(interaction_count=500)
        state = {**empty_state, "decoy_inventory": [burned]}
        result = rotate_decoys(state)
        for action in result["rotation_actions"]:
            assert "timestamp" in action

    def test_empty_inventory_no_retirements(self, empty_state):
        from deception_honeypot_agent.nodes.rotate_decoys import rotate_decoys

        result = rotate_decoys(empty_state)
        retired = [a for a in result["rotation_actions"] if a["action"] == "retire"]
        assert len(retired) == 0
