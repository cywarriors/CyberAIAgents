"""Shared API dependencies."""
from __future__ import annotations
from compliance_audit_agent.monitoring.store import get_store as _get_store

def get_store():
    return _get_store()
