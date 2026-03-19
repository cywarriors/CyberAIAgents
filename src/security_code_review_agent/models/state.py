from __future__ import annotations
from typing import Any
from pydantic import BaseModel


class CodeReviewState(BaseModel):
    scan_target: dict[str, Any] = {}          # repo/PR metadata
    sast_findings: list[dict[str, Any]] = []
    secrets_findings: list[dict[str, Any]] = []
    sca_findings: list[dict[str, Any]] = []
    fix_suggestions: list[dict[str, Any]] = []
    policy_verdict: dict[str, Any] = {}
    sbom: dict[str, Any] = {}
    pr_comments: list[dict[str, Any]] = []
    lifecycle_updates: list[dict[str, Any]] = []
    processing_errors: list[str] = []
