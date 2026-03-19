from __future__ import annotations
from pydantic import BaseModel
from typing import Any


class DeceptionState(BaseModel):
    decoy_inventory: list[dict[str, Any]] = []
    honey_credentials: list[dict[str, Any]] = []
    canary_tokens: list[dict[str, Any]] = []
    interactions: list[dict[str, Any]] = []
    classified_interactions: list[dict[str, Any]] = []
    ttp_mappings: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    attacker_profiles: list[dict[str, Any]] = []
    coverage_assessment: dict[str, Any] = {}
    rotation_actions: list[dict[str, Any]] = []
    processing_errors: list[str] = []
