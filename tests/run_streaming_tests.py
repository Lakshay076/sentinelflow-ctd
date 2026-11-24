"""
Direct test runner for Real-Time Streaming and IPC components.
"""

import asyncio
import json
import os
import sys
import time

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.routes.stream import StreamConnectionManager, receive_internal_event
from telemetry.ipc_client import LocalIPCClient


class MockWebSocket:
    def __init__(self):
        self.accepted = False
        self.messages = []

    async def accept(self):
        self.accepted = True

    async def send_text(self, text: str):
        self.messages.append(text)


class MockRequest:
    def __init__(self, host="127.0.0.1", payload=None):
        self.client = type("Client", (), {"host": host})()
        self._payload = payload or {}

    async def json(self):
        return self._payload


def test_ipc_client():
    print("[1/4] Testing LocalIPCClient non-blocking behavior...", flush=True)
    ipc = LocalIPCClient(
        endpoint_url="http://127.0.0.1:9999/nonexistent",
        queue_size=10,
        request_timeout=0.1,
    )
    # Intercept HTTP dispatch to avoid waiting for network timeouts
    dispatched = []
    ipc._dispatch_http = lambda event: dispatched.append(event)
    
    ipc.publish_telemetry_window({"packets_per_second": 100.0, "timestamp": time.time()})
    ipc.publish_alert_created({"alert_id": 999, "attack_type": "SYN_FLOOD"})
    ipc.publish_alert_updated({"alert_id": 999, "event_count": 2})
    ipc.publish_alert_resolved({"alert_id": 999, "status": "RESOLVED"})
    
    time.sleep(0.1)
    ipc.stop()
    assert len(dispatched) >= 1, "Expected dispatched calls"
    print("  ✓ LocalIPCClient successfully enqueues and dispatches events non-blockingly", flush=True)


async def test_stream_manager():
    print("[2/4] Testing StreamConnectionManager broadcast & latency injection...", flush=True)
    manager = StreamConnectionManager()
    mock_ws = MockWebSocket()
    
    await manager.connect(mock_ws)
    assert len(manager.active_connections) == 1, "Expected 1 connection"
    assert mock_ws.accepted is True, "Expected WebSocket to be accepted"

    event = {
        "event_type": "TELEMETRY_WINDOW",
        "window_timestamp": time.time() - 0.05,
        "data": {"packets_per_second": 45.0},
    }
    await manager.broadcast(event)

    assert len(mock_ws.messages) >= 2, "Expected handshake + broadcast messages"
    last_call = json.loads(mock_ws.messages[-1])
    assert last_call["event_type"] == "TELEMETRY_WINDOW"
    assert "dispatched_at" in last_call, "Expected dispatched_at timestamp"
    assert "window_timestamp" in last_call, "Expected window_timestamp"

    manager.disconnect(mock_ws)
    assert len(manager.active_connections) == 0, "Expected 0 connections after disconnect"
    print("  ✓ StreamConnectionManager connects, injects timestamps, and broadcasts cleanly", flush=True)


async def test_internal_endpoint():
    print("[3/4] Testing /api/internal/events loopback security restriction...", flush=True)
    # 1. Non-loopback must be rejected (403)
    ext_req = MockRequest(host="192.168.1.100")
    rejected = False
    try:
        await receive_internal_event(ext_req)
    except Exception as exc:
        if getattr(exc, "status_code", None) == 403:
            rejected = True
    assert rejected, "Non-loopback caller must receive HTTP 403 Forbidden"

    # 2. Loopback must be accepted (200)
    loopback_req = MockRequest(
        host="127.0.0.1",
        payload={
            "event_type": "ALERT_CREATED",
            "data": {"alert_id": 1, "attack_type": "PORT_SCAN"},
        },
    )
    resp = await receive_internal_event(loopback_req)
    assert resp["status"] == "ok", "Expected status ok"
    print("  ✓ Loopback restriction strictly enforces local-only IPC security", flush=True)


def test_sync_wrapper():
    print("[4/4] Testing broadcast_sync wrapper from synchronous routes...", flush=True)
    manager = StreamConnectionManager()
    manager.broadcast_sync({"event_type": "PING"})
    print("  ✓ broadcast_sync executes safely from synchronous contexts", flush=True)


async def run_async_tests():
    await test_stream_manager()
    await test_internal_endpoint()


def main():
    print("=" * 70, flush=True)
    print("SENTINELFLOW-CTD — REAL-TIME STREAMING & IPC TEST SUITE", flush=True)
    print("=" * 70, flush=True)
    test_ipc_client()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run_async_tests())
    finally:
        loop.close()
    test_sync_wrapper()
    print("=" * 70, flush=True)
    print("ALL REAL-TIME STREAMING & IPC TESTS PASSED SUCCESSFULLY! ✓", flush=True)
    print("=" * 70, flush=True)


if __name__ == "__main__":
    main()
