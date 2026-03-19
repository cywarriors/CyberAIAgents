"""Admin routes: health, config, statistics."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..dependencies import get_store
from ..store import InMemoryStore
from ...config import get_settings

router = APIRouter(tags=["admin"])


@router.get("/admin/health")
def health() -> dict:
    return {"status": "ok", "agent": "deception-honeypot"}


@router.get("/admin/config")
def config() -> dict:
    s = get_settings()
    return {
        "api_port": s.api_port,
        "health_port": s.health_port,
        "metrics_port": s.metrics_port,
        "max_decoys": s.max_decoys,
        "rotation_interval_hours": s.rotation_interval_hours,
        "coverage_target_percent": s.coverage_target_percent,
        "log_level": s.log_level,
    }


@router.get("/admin/statistics")
def statistics(store: InMemoryStore = Depends(get_store)) -> dict:
    return store.get_statistics()
