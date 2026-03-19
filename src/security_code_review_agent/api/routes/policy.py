from __future__ import annotations
from typing import Any
from fastapi import APIRouter
from security_code_review_agent.api.store import get_data_store

router = APIRouter(prefix="/api/v1/policy", tags=["policy"])


@router.get("/verdicts")
async def list_verdicts() -> list[dict[str, Any]]:
    return get_data_store().get_policy_verdicts()
