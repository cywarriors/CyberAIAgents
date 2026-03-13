"""Unit tests for posture drift tracking node."""

import pytest
from cloud_security_agent.models import CloudProvider, ExposureLevel
from cloud_security_agent.models.state import CloudPostureState
from cloud_security_agent.nodes.drift import track_posture_drift, _config_hash
from tests_cspm.mocks.generators import MockDataGenerator


class TestConfigHash:
    """Tests for _config_hash utility."""

    def test_same_dict_same_hash(self):
        d = {"encryption_enabled": True, "public_access_enabled": False}
        assert _config_hash(d) == _config_hash(d)

    def test_key_order_independent(self):
        a = {"b": 2, "a": 1}
        b = {"a": 1, "b": 2}
        assert _config_hash(a) == _config_hash(b)

    def test_different_values_different_hash(self):
        a = {"encryption_enabled": True}
        b = {"encryption_enabled": False}
        assert _config_hash(a) != _config_hash(b)


@pytest.mark.asyncio
class TestDriftDetection:
    """Tests for the track_posture_drift node."""

    async def test_no_previous_snapshot_produces_no_drift(self):
        state = CloudPostureState()
        state.resource_inventory = [
            MockDataGenerator.generate_resource(name="bucket-1")
        ]
        state.previous_snapshot = []

        result = await track_posture_drift(state)
        assert len(result.drift_records) == 0
        assert result.metrics["drift_total"] == 0

    async def test_identical_snapshots_no_drift(self):
        resource = MockDataGenerator.generate_resource(name="bucket-1")
        state = CloudPostureState()
        state.resource_inventory = [resource]
        state.previous_snapshot = [resource]

        result = await track_posture_drift(state)
        assert len(result.drift_records) == 0

    async def test_encryption_disabled_is_regression(self):
        current = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"encryption_enabled": False},
        )
        previous = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"encryption_enabled": True},
        )
        state = CloudPostureState()
        state.resource_inventory = [current]
        state.previous_snapshot = [previous]

        result = await track_posture_drift(state)
        regressions = [d for d in result.drift_records if d.drift_type == "security_regression"]
        assert len(regressions) >= 1
        assert any(d.field_changed == "encryption_enabled" for d in regressions)

    async def test_encryption_enabled_is_improvement(self):
        current = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"encryption_enabled": True},
        )
        previous = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"encryption_enabled": False},
        )
        state = CloudPostureState()
        state.resource_inventory = [current]
        state.previous_snapshot = [previous]

        result = await track_posture_drift(state)
        improvements = [d for d in result.drift_records if d.drift_type == "improvement"]
        assert len(improvements) >= 1
        assert any(d.field_changed == "encryption_enabled" for d in improvements)

    async def test_public_access_enabled_is_regression(self):
        current = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"public_access_enabled": True},
        )
        previous = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"public_access_enabled": False},
        )
        state = CloudPostureState()
        state.resource_inventory = [current]
        state.previous_snapshot = [previous]

        result = await track_posture_drift(state)
        assert result.metrics["drift_regressions"] >= 1

    async def test_tls_upgrade_is_improvement(self):
        current = MockDataGenerator.generate_resource(
            name="stor-1",
            resource_type="storage_account",
            provider=CloudProvider.AZURE,
            config_overrides={"tls_version": "1.2"},
        )
        previous = MockDataGenerator.generate_resource(
            name="stor-1",
            resource_type="storage_account",
            provider=CloudProvider.AZURE,
            config_overrides={"tls_version": "1.0"},
        )
        state = CloudPostureState()
        state.resource_inventory = [current]
        state.previous_snapshot = [previous]

        result = await track_posture_drift(state)
        improvements = [d for d in result.drift_records if d.drift_type == "improvement"]
        assert any(d.field_changed == "tls_version" for d in improvements)

    async def test_non_security_field_is_neutral(self):
        current = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"tags": {"env": "staging"}},
        )
        previous = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"tags": {"env": "prod"}},
        )
        state = CloudPostureState()
        state.resource_inventory = [current]
        state.previous_snapshot = [previous]

        result = await track_posture_drift(state)
        neutrals = [d for d in result.drift_records if d.drift_type == "neutral"]
        assert len(neutrals) >= 1

    async def test_new_resource_not_detected_as_drift(self):
        """A resource present in current but not in previous is not drift."""
        state = CloudPostureState()
        state.resource_inventory = [
            MockDataGenerator.generate_resource(name="new-bucket", config_overrides={"encryption_enabled": False}),
        ]
        state.previous_snapshot = [
            MockDataGenerator.generate_resource(name="old-bucket"),
        ]

        result = await track_posture_drift(state)
        # new-bucket not in previous snapshot so no records for it
        assert all(d.resource_id != state.resource_inventory[0].resource_id for d in result.drift_records)

    async def test_metrics_populated(self):
        current = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"encryption_enabled": False, "public_access_enabled": True},
        )
        previous = MockDataGenerator.generate_resource(
            name="bucket-1",
            config_overrides={"encryption_enabled": True, "public_access_enabled": False},
        )
        state = CloudPostureState()
        state.resource_inventory = [current]
        state.previous_snapshot = [previous]

        result = await track_posture_drift(state)
        assert "drift_total" in result.metrics
        assert "drift_regressions" in result.metrics
        assert "drift_improvements" in result.metrics
        assert result.metrics["drift_total"] >= 2  # at least 2 changes

    async def test_pre_existing_drift_records_preserved(self):
        """When drift_records already populated, they are kept as-is."""
        state = CloudPostureState()
        existing = [MockDataGenerator.generate_drift_record("security_regression")]
        state.drift_records = existing

        result = await track_posture_drift(state)
        assert result.drift_records == existing
        assert result.metrics["drift_regressions"] == 1
