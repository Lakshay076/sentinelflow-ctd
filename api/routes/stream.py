"""
Real-time WebSocket Streaming & Internal IPC Route.

Provides:
1. /ws/live - Full-duplex WebSocket stream for React dashboard clients.
2. /api/internal/events - Local loopback webhook for Packet Collector process.
"""

import json
import logging
import time
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect

logger = logging.getLogger("ctd.stream")

router = APIRouter(tags=["Real-Time Stream"])


class StreamConnectionManager:
    """Manages active dashboard WebSocket subscribers and event broadcasting."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"[Stream] Client connected. Total active subscribers: {len(self.active_connections)}"
        )
        # Send initial connection handshake
        try:
            await websocket.send_text(
                json.dumps(
                    {
                        "event_type": "CONNECTED",
                        "server_time": time.time(),
                        "message": "CTD Live Stream Connected",
                    }
                )
            )
        except Exception:
            pass

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                f"[Stream] Client disconnected. Total active subscribers: {len(self.active_connections)}"
            )

    async def broadcast(self, event: Dict[str, Any]):
        """
        Broadcasts structured event payloads to all connected clients.
        Adds dispatched_at timestamp for client-side latency calculation.
        """
        if not self.active_connections:
            return

        # Inject server dispatch timestamp for delivery latency measurement
        event["dispatched_at"] = time.time()
        payload = json.dumps(event)

        stale_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                stale_connections.append(connection)

        for stale in stale_connections:
            self.disconnect(stale)

    def broadcast_sync(self, event: Dict[str, Any]):
        """Synchronous wrapper to broadcast an event when called from synchronous routes."""
        if not self.active_connections:
            return
        try:
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                asyncio.create_task(self.broadcast(event))
            except RuntimeError:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self.broadcast(event))
                loop.close()
        except Exception as exc:
            logger.debug(f"[Stream] broadcast_sync error: {exc}")


stream_manager = StreamConnectionManager()


@router.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket):
    """
    WebSocket endpoint for real-time telemetry and security alert events.
    Replaces periodic polling with push updates.
    """
    await stream_manager.connect(websocket)
    try:
        while True:
            # Keep socket open and accept incoming ping/heartbeat text from client
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        stream_manager.disconnect(websocket)
    except Exception as exc:
        logger.debug(f"[Stream] WebSocket error: {exc}")
        stream_manager.disconnect(websocket)


@router.post("/api/internal/events")
async def receive_internal_event(request: Request):
    """
    Internal loopback webhook for the Packet Collector process.
    Restricted to loopback (127.0.0.1 / ::1) to ensure no external access.
    """
    client_host = request.client.host if request.client else "unknown"
    if client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Internal events endpoint is restricted to local loopback.",
        )

    try:
        event = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    if not isinstance(event, dict) or "event_type" not in event:
        raise HTTPException(status_code=400, detail="Missing event_type in payload")

    # Broadcast event to all active dashboard WebSocket subscribers
    await stream_manager.broadcast(event)

    return {
        "status": "ok",
        "subscribers": len(stream_manager.active_connections),
    }
