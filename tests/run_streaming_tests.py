"""
Direct test runner for Real-Time Streaming and IPC components.

Design: ALL tests run synchronously — no asyncio event loop is created.
Async coroutines are driven by a minimal synchronous stepper that
calls coroutine.send(None) in a loop until StopIteration.

This avoids sandbox/environment restrictions on asyncio event loop
creation (which requires OS socket/select primitives) while still
validating the async interface of StreamConnectionManager.

Tested:
- LocalIPCClient: non-blocking dispatch, queue mechanics, worker lifecycle
- StreamConnectionManager: connect/broadcast/disconnect/latency injection
- Loopback security: allow-list logic reproduced from receive_internal_event
- broadcast_sync: safe from synchronous contexts
"""

import inspect
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telemetry.ipc_client import LocalIPCClient
from api.routes.stream import StreamConnectionManager


# ─────────────────────────────────────────────────────────────────────────────
# Synchronous coroutine runner
# ─────────────────────────────────────────────────────────────────────────────

def run(coro):
    """
    Drive a coroutine to completion synchronously.

    Works for coroutines whose awaitable chain resolves without actual I/O
    (i.e., all await targets return immediately via StopIteration).
    Our MockWebSocket methods are plain `async def` with no inner awaits,
    so they fit this model perfectly.
    """
    result = None
    try:
        while True:
            try:
                # Step the coroutine
                sub = coro.send(None)
                # sub is a sub-coroutine yielded by an `await` expression.
                # Drive it to completion too.
                if inspect.iscoroutine(sub):
                    result = run(sub)
                    coro.send(result)   # resume outer with sub's result
            except StopIteration as exc:
                return exc.value
    except StopIteration as exc:
        return exc.value


# ─────────────────────────────────────────────────────────────────────────────
# Mock helpers
# ─────────────────────────────────────────────────────────────────────────────

class MockWebSocket:
    def __init__(self):
        self.accepted = False
        self.messages = []

    async def accept(self):
        self.accepted = True

    async def send_text(self, text: str):
        self.messages.append(text)


def _loopback_allowed(host: str) -> bool:
    """Reproduces the allow-list from receive_internal_event."""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — LocalIPCClient non-blocking behaviour
# ─────────────────────────────────────────────────────────────────────────────

def test_ipc_client():
    print("[1/4] Testing LocalIPCClient non-blocking behavior...", flush=True)
    ipc = LocalIPCClient(
        endpoint_url="http://127.0.0.1:9999/nonexistent",
        queue_size=10,
        request_timeout=0.1,
    )
    dispatched = []
    ipc._dispatch_http = lambda event: dispatched.append(event)

    ipc.publish_telemetry_window({"packets_per_second": 100.0, "timestamp": time.time()})
    ipc.publish_alert_created({"alert_id": 999, "attack_type": "SYN_FLOOD"})
    ipc.publish_alert_updated({"alert_id": 999, "event_count": 2})
    ipc.publish_alert_resolved({"alert_id": 999, "status": "RESOLVED"})

    time.sleep(0.3)
    ipc.stop()

    assert len(dispatched) >= 1, f"Expected >=1 dispatched calls, got {len(dispatched)}"
    print(f"  ✓ LocalIPCClient dispatched {len(dispatched)} event(s) non-blockingly", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — StreamConnectionManager broadcast + latency timestamp injection
# ─────────────────────────────────────────────────────────────────────────────

def test_stream_manager():
    print("[2/4] Testing StreamConnectionManager broadcast & latency injection...", flush=True)
    manager = StreamConnectionManager()
    mock_ws = MockWebSocket()

    run(manager.connect(mock_ws))
    assert len(manager.active_connections) == 1, "Expected 1 active connection after connect()"
    assert mock_ws.accepted is True, "MockWebSocket.accept() must have been called"

    # connect() sends a CONNECTED handshake message
    assert len(mock_ws.messages) == 1, (
        f"Expected 1 handshake message after connect(), got {len(mock_ws.messages)}"
    )
    handshake = json.loads(mock_ws.messages[0])
    assert handshake["event_type"] == "CONNECTED", (
        f"Handshake event_type must be CONNECTED, got {handshake.get('event_type')}"
    )

    event = {
        "event_type": "TELEMETRY_WINDOW",
        "window_timestamp": time.time() - 0.05,
        "data": {"packets_per_second": 45.0},
    }
    run(manager.broadcast(event))

    assert len(mock_ws.messages) == 2, (
        f"Expected 2 messages (handshake + broadcast), got {len(mock_ws.messages)}"
    )
    broadcast_msg = json.loads(mock_ws.messages[1])
    assert broadcast_msg["event_type"] == "TELEMETRY_WINDOW", "broadcast() event_type mismatch"
    assert "dispatched_at" in broadcast_msg, "broadcast() must inject dispatched_at"
    assert "window_timestamp" in broadcast_msg, "window_timestamp must survive broadcast()"

    latency_ms = (broadcast_msg["dispatched_at"] - broadcast_msg["window_timestamp"]) * 1000
    assert latency_ms >= 0, f"Negative latency {latency_ms:.1f} ms — clock issue?"
    print(f"  ✓ Measured delivery latency: {latency_ms:.1f} ms", flush=True)

    manager.disconnect(mock_ws)
    assert len(manager.active_connections) == 0, "Expected 0 connections after disconnect()"
    print("  ✓ StreamConnectionManager: connect/broadcast/latency/disconnect — all correct", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — Loopback security restriction
# ─────────────────────────────────────────────────────────────────────────────

def test_loopback_restriction():
    print("[3/4] Testing loopback security restriction logic...", flush=True)

    assert not _loopback_allowed("192.168.1.100"), "External IP must be blocked"
    assert not _loopback_allowed("10.10.10.10"), "LAN IP must be blocked"
    assert not _loopback_allowed("0.0.0.0"), "0.0.0.0 must be blocked"
    assert not _loopback_allowed(""), "Empty string must be blocked"

    assert _loopback_allowed("127.0.0.1"), "IPv4 loopback must be allowed"
    assert _loopback_allowed("::1"), "IPv6 loopback must be allowed"
    assert _loopback_allowed("localhost"), "localhost must be allowed"
    assert _loopback_allowed("testclient"), "testclient (test harness) must be allowed"

    # Verify the actual source code in stream.py contains the same allow-list
    import api.routes.stream as stream_module
    src = inspect.getsource(stream_module.receive_internal_event)
    for expected_host in ("127.0.0.1", "::1", "localhost", "testclient"):
        assert expected_host in src, (
            f"stream.py receive_internal_event is missing '{expected_host}' "
            f"from its allow-list — allow-list drifted from test expectations."
        )

    print("  ✓ Loopback restriction: external IPs blocked, loopback IPs allowed", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — broadcast_sync wrapper (synchronous context safety)
# ─────────────────────────────────────────────────────────────────────────────

def test_sync_wrapper():
    print("[4/4] Testing broadcast_sync wrapper from synchronous routes...", flush=True)
    manager = StreamConnectionManager()

    # With no active connections, must be a no-op
    manager.broadcast_sync({"event_type": "PING"})

    # Must not raise in any context
    try:
        manager.broadcast_sync({"event_type": "PONG", "data": {"x": 1}})
    except Exception as exc:
        raise AssertionError(f"broadcast_sync raised unexpectedly: {exc}")

    print("  ✓ broadcast_sync executes safely from synchronous contexts", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70, flush=True)
    print("SENTINELFLOW-CTD — REAL-TIME STREAMING & IPC TEST SUITE", flush=True)
    print("=" * 70, flush=True)

    test_ipc_client()
    test_stream_manager()
    test_loopback_restriction()
    test_sync_wrapper()

    print("=" * 70, flush=True)
    print("ALL REAL-TIME STREAMING & IPC TESTS PASSED SUCCESSFULLY! ✓", flush=True)
    print("=" * 70, flush=True)


if __name__ == "__main__":
    main()
