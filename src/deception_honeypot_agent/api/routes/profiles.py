"""Attacker profile routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..dependencies import get_store
from ..store import InMemoryStore

router = APIRouter(prefix="/api/v1/attacker-profiles", tags=["profiles"])


@router.get("")
def list_profiles(store: InMemoryStore = Depends(get_store)) -> dict:
    profiles = store.get_profiles()
    return {"items": profiles, "total": len(profiles)}
