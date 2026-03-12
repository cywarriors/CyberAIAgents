"""Unit tests for RecommendActionsNode."""

from incident_triage_agent.nodes.recommend import recommend_actions
from tests_triage.mocks.generators import (
    generate_brute_force_alert,
    generate_data_exfil_alert,
    generate_dns_tunnelling_alert,
    generate_benign_auth_alert,
)


def _make_state(alerts, entity_context=None, classifications=None):
    return {
        "raw_alerts": alerts,
        "entity_context": entity_context or [],
        "classifications": classifications or [],
    }


class TestRecommendActions:
    def test_produces_actions_for_brute_force(self):
        alert = generate_brute_force_alert()
        result = recommend_actions(_make_state([alert]))
        actions = result["recommended_actions"]
        assert len(actions) > 0
        assert any("account" in a["title"].lower() or "login" in a["title"].lower()
                    or "credential" in a["title"].lower() or "mfa" in a["title"].lower()
                    for a in actions)

    def test_produces_actions_for_exfil(self):
        alert = generate_data_exfil_alert()
        result = recommend_actions(_make_state([alert]))
        actions = result["recommended_actions"]
        assert any(a["action_type"] == "contain" for a in actions)

    def test_dns_tunnelling_actions(self):
        alert = generate_dns_tunnelling_alert()
        result = recommend_actions(_make_state([alert]))
        actions = result["recommended_actions"]
        assert any("domain" in a["title"].lower() or "dns" in a["title"].lower()
                    or "isolate" in a["title"].lower() for a in actions)

    def test_default_actions_for_unknown(self):
        alert = generate_benign_auth_alert()
        result = recommend_actions(_make_state([alert]))
        actions = result["recommended_actions"]
        assert len(actions) > 0
        # Should get default actions since no MITRE techniques match
        assert any("context" in a["title"].lower() or "escalate" in a["title"].lower()
                    for a in actions)

    def test_actions_sorted_by_type(self):
        """Contain actions should come before investigate which come before escalate."""
        alert = generate_data_exfil_alert()
        entity_context = [
            {"entity_type": "host", "entity_id": "srv-db-01"},
            {"entity_type": "ip", "entity_id": "198.51.100.12"},
        ]
        result = recommend_actions(_make_state([alert], entity_context))
        actions = result["recommended_actions"]
        types = [a["action_type"] for a in actions]
        type_order = {"contain": 0, "investigate": 1, "escalate": 2, "notify": 3}
        orders = [type_order.get(t, 9) for t in types]
        assert orders == sorted(orders)

    def test_no_duplicate_actions(self):
        alert = generate_brute_force_alert()
        result = recommend_actions(_make_state([alert]))
        titles = [a["title"] for a in result["recommended_actions"]]
        assert len(titles) == len(set(titles))

    def test_action_ids_unique(self):
        alert = generate_data_exfil_alert()
        result = recommend_actions(_make_state([alert]))
        ids = [a["action_id"] for a in result["recommended_actions"]]
        assert len(ids) == len(set(ids))

    def test_priority_order_sequential(self):
        alert = generate_brute_force_alert()
        result = recommend_actions(_make_state([alert]))
        actions = result["recommended_actions"]
        orders = [a["priority_order"] for a in actions]
        assert orders == list(range(1, len(orders) + 1))
