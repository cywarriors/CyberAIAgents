"""Shared FastAPI dependencies."""
from __future__ import annotations

from .store import InMemoryStore, get_data_store


def get_store() -> InMemoryStore:
    return get_data_store()
