"""WebSocket endpoints – scan streaming and live notifications."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from vapt_agent.api.dependencies import get_store

router = APIRouter(tags=["websocket"])

# Track connected notification clients
_notification_clients: list[WebSocket] = []


@router.websocket("/api/v1/scans/{scan_id}/stream")
async def scan_stream(websocket: WebSocket, scan_id: str):
    """Stream scan progress events for a specific scan."""
    store = get_store()
    scan = store.scans.get(scan_id)
    if not scan:
        await websocket.close(code=4004, reason="Scan not found")
        return

    await websocket.accept()
    try:
        progress = scan.get("progress", 0)
        while progress < 100 and scan.get("status") == "running":
            await websocket.send_json(
                {
                    "type": "scan_progress",
                    "scan_id": scan_id,
                    "progress": progress,
                    "status": scan.get("status", "running"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            await asyncio.sleep(2)
            scan = store.scans.get(scan_id, scan)
            progress = scan.get("progress", progress)

        # Send final status
        await websocket.send_json(
            {
                "type": "scan_complete",
                "scan_id": scan_id,
                "progress": 100,
                "status": scan.get("status", "completed"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except WebSocketDisconnect:
        pass


@router.websocket("/ws/notifications")
async def notifications(websocket: WebSocket):
    """Global notification stream for real-time alerts."""
    await websocket.accept()
    _notification_clients.append(websocket)
    try:
        while True:
            # Keep connection alive; clients receive pushed events
            data = await websocket.receive_text()
            # Echo for ping-pong keepalive
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        _notification_clients.remove(websocket)


async def broadcast_notification(event_type: str, payload: dict) -> None:
    """Utility to push a notification to all connected clients."""
    message = json.dumps(
        {
            "type": event_type,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    disconnected: list[WebSocket] = []
    for ws in _notification_clients:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        _notification_clients.remove(ws)
