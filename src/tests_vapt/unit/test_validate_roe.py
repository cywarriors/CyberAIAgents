"""Unit tests for Node 1 – ValidateRoE."""

from __future__ import annotations

import pytest
from vapt_agent.nodes.validate_roe import validate_roe
from tests_vapt.mocks.generators import (
    generate_valid_roe,
    generate_expired_roe,
    generate_incomplete_roe,
)


class TestValidateRoE:
    """Test suite for RoE validation node."""

    def test_valid_roe_passes(self):
        roe = generate_valid_roe()
        result = validate_roe({"roe_authorization": roe})
        assert result["roe_validated"] is True
        assert "engagement_id" in result

    def test_missing_roe_fails(self):
        result = validate_roe({})
        assert result["roe_validated"] is False
        assert len(result["errors"]) >= 1

    def test_empty_roe_fails(self):
        result = validate_roe({"roe_authorization": {}})
        assert result["roe_validated"] is False

    def test_incomplete_roe_fails(self):
        roe = generate_incomplete_roe()
        result = validate_roe({"roe_authorization": roe})
        assert result["roe_validated"] is False
        errors = result.get("errors", [])
        assert any("missing" in e.get("message", "").lower() for e in errors)

    def test_expired_roe_fails(self):
        roe = generate_expired_roe()
        result = validate_roe({"roe_authorization": roe})
        assert result["roe_validated"] is False

    def test_preserves_existing_engagement_id(self):
        roe = generate_valid_roe()
        result = validate_roe(
            {"roe_authorization": roe, "engagement_id": "my-custom-id"}
        )
        assert result["roe_validated"] is True
        assert result["engagement_id"] == "my-custom-id"

    def test_destructive_flag_preserved(self):
        roe = generate_valid_roe(allow_destructive=True)
        result = validate_roe({"roe_authorization": roe})
        assert result["roe_validated"] is True
