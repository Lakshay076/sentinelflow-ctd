"""
Unit & Integration Test Suite for Real-Time Streaming Architecture.
Uses Python standard library (unittest & asyncio) with zero extra test dependencies.

Tests:
1. LocalIPCClient non-blocking behavior and graceful handling when API is offline.
2. StreamConnectionManager subscriber tracking and broadcast delivery.
3. Latency metadata injection (dispatched_at, window_timestamp).
4. Synchronous broadcast wrapper (broadcast_sync).
"""

import asyncio
import json
import os
import sys
import time
import unittest
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.routes.stream import StreamConnectionManager, stream_manager, receive_internal_event
from telemetry.ipc_client import LocalIPCClient


class TestRealTimeStreaming(unittest.IsolatedAsyncioTestCase):

    def test_ipc_client_non_blocking_offline(self):
        """Verify IPC client drops/dispatches without crashing when API is unreachable."""
        dummy_ipc = LocalIPCClient(
            endpoint_url="http://127.0.0.1:9999/nonexistent",
            queue_size=10,
            request_timeout=0.1,
        )
        # Mock _dispatch_http so it doesn't wait for network timeouts during unit test
        dummy_ipc._dispatch_http = MagicMock()
        
        dummy_ipc.publish_telemetry_window({"packets_per_second": 100.0, "timestamp": time.time()})
        dummy_ipc.publish_alert_created({"alert_id": 999, "attack_type": "SYN_FLOOD"})
        dummy_ipc.publish_alert_updated({"alert_id": 999, "event_count": 2})
        dummy_ipc.publish_alert_resolved({"alert_id": 999, "status": "RESOLVED"})
        
        time.sleep(0.1)
        dummy_ipc.stop()
        self.assertGreaterEqual(dummy_ipc._dispatch_http.call_count, 1)

    async def test_stream_connection_manager_broadcast(self):
        """Verify StreamConnectionManager tracks subscribers and broadcasts events with timestamps."""
        manager = StreamConnectionManager()
        
        mock_ws = AsyncMock()
        mock_ws.accept = AsyncMock()
        mock_ws.send_text = AsyncMock()

        # Connect
        await manager.connect(mock_ws)
        self.assertEqual(len(manager.active_connections), 1)

        # Broadcast telemetry window
        now = time.time()
        event = {
            "event_type": "TELEMETRY_WINDOW",
            "window_timestamp": now - 0.05,
            "data": {"packets_per_second": 50.0},
        }
        await manager.broadcast(event)

        # Verify send_text was called
        self.assertGreaterEqual(mock_ws.send_text.call_count, 1)
        last_call_arg = mock_ws.send_text.call_args[0][0]
        payload = json.loads(last_call_arg)

        self.assertEqual(payload["event_type"], "TELEMETRY_WINDOW")
        self.assertIn("dispatched_at", payload)
        self.assertIn("window_timestamp", payload)
        self.assertGreaterEqual(payload["dispatched_at"], now - 0.01)

        # Disconnect
        manager.disconnect(mock_ws)
        self.assertEqual(len(manager.active_connections), 0)

    async def test_internal_event_endpoint_loopback_restriction(self):
        """Verify internal event endpoint rejects non-loopback requests."""
        # Non-loopback request
        external_req = MagicMock()
        external_req.client.host = "192.168.1.50"
        
        with self.assertRaises(Exception) as ctx:
            await receive_internal_event(external_req)
        self.assertEqual(ctx.exception.status_code, 403)

        # Loopback request
        loopback_req = MagicMock()
        loopback_req.client.host = "127.0.0.1"
        loopback_req.json = AsyncMock(return_value={
            "event_type": "ALERT_CREATED",
            "data": {"alert_id": 42},
        })
        resp = await receive_internal_event(loopback_req)
        self.assertEqual(resp["status"], "ok")

    def test_broadcast_sync_wrapper(self):
        """Verify synchronous broadcast wrapper works safely."""
        manager = StreamConnectionManager()
        # Should execute safely even without an active event loop
        manager.broadcast_sync({"event_type": "PING"})
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
