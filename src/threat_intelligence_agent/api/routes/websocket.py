"""WebSocket endpoint for real-time IOC and brief notifications."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["websocket"])

_MAX_CONNECTIONS = 50
_connections: list[WebSocket] = []


@router.websocket("/ws/notifications")
async def notifications_ws(websocket: WebSocket):
    if len(_connections) >= _MAX_CONNECTIONS:
        await websocket.close(code=1013, reason="Too many connections")
        return

    await websocket.accept()
    _connections.append(websocket)
    try:
        while True:
            # Keep connection alive; client can send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _connections:
            _connections.remove(websocket)


async def broadcast_notification(event_type: str, payload: dict) -> None:
    """Broadcast a notification to all connected clients."""
    message = json.dumps({"type": event_type, "data": payload})
    disconnected: list[WebSocket] = []
    for ws in _connections:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        if ws in _connections:
            _connections.remove(ws)
