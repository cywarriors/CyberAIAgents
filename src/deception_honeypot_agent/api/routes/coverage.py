"""Coverage assessment route."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..dependencies import get_store
from ..store import InMemoryStore

router = APIRouter(prefix="/api/v1/coverage", tags=["coverage"])


@router.get("")
def get_coverage(store: InMemoryStore = Depends(get_store)) -> dict:
    coverage = store.get_coverage()
    if not coverage:
        return {
            "coverage_percent": 0.0,
            "deployed_types": [],
            "missing_types": [],
            "recommendations": [],
        }
    return coverage
