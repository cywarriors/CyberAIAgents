"""Decoy asset routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..dependencies import get_store
from ..store import InMemoryStore

router = APIRouter(prefix="/api/v1/decoys", tags=["decoys"])


@router.get("")
def list_decoys(store: InMemoryStore = Depends(get_store)) -> dict:
    decoys = store.get_decoys()
    return {"items": decoys, "total": len(decoys)}


@router.get("/{decoy_id}")
def get_decoy(decoy_id: str, store: InMemoryStore = Depends(get_store)) -> dict:
    for d in store.get_decoys():
        if d.get("decoy_id") == decoy_id:
            return d
    raise HTTPException(status_code=404, detail="Decoy not found")
