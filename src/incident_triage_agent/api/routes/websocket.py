"""WebSocket endpoints for real-time incident streaming."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from incident_triage_agent.api.dependencies import get_store

router = APIRouter(tags=["websocket"])


@router.websocket("/api/v1/incidents/stream")
async def incident_stream(websocket: WebSocket):
    await websocket.accept()
    store = get_store()
    seen_ids: set[str] = set(store.incidents.keys())

    try:
        while True:
            current_ids = set(store.incidents.keys())
            new_ids = current_ids - seen_ids
            for iid in sorted(new_ids):
                inc = store.incidents[iid]
                await websocket.send_json(inc)
            seen_ids = current_ids
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass


@router.websocket("/ws/notifications")
async def notifications(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
            parsed = json.loads(data)
            if parsed.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
