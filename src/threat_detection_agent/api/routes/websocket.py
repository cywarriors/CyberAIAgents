"""WebSocket endpoints for real-time alert and notification streams."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from threat_detection_agent.api.dependencies import get_store

router = APIRouter(tags=["websocket"])

_notification_clients: list[WebSocket] = []


@router.websocket("/api/v1/alerts/stream")
async def alert_stream(ws: WebSocket):
    """Stream new alerts in real time."""
    await ws.accept()
    store = get_store()
    seen: set[str] = set(store.alerts.keys())
    try:
        while True:
            current = set(store.alerts.keys())
            new_ids = current - seen
            for aid in new_ids:
                alert = store.alerts.get(aid)
                if alert:
                    await ws.send_text(json.dumps(alert))
            seen = current
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass


@router.websocket("/ws/notifications")
async def notifications(ws: WebSocket):
    """Global notification channel."""
    await ws.accept()
    _notification_clients.append(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        _notification_clients.remove(ws)


async def broadcast_notification(payload: dict) -> None:
    for ws in list(_notification_clients):
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            _notification_clients.remove(ws)
