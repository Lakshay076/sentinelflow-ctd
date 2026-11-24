"""
Local Inter-Process Communication (IPC) Event Dispatcher.

Transfers telemetry and alert lifecycle events from the Packet Collector
process to the FastAPI process on the Monitoring VM via a local loopback webhook.

Design Principles:
1. Non-blocking: Uses a bounded background queue and daemon worker thread.
2. Safe: If FastAPI is not running or slow, events are dropped without
   delaying Scapy packet capture or window evaluations.
3. Zero-dependency: Uses Python standard library only (queue, threading, urllib).
4. Strictly local: Connects exclusively to 127.0.0.1 (loopback), ensuring no
   packets or control signals leave the monitoring management environment.
"""

import json
import logging
import queue
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

logger = logging.getLogger("ctd.ipc")


class LocalIPCClient:
    """
    Lightweight, thread-safe asynchronous event dispatcher.
    Runs a daemon worker thread that drains a bounded queue and POSTs
    events to the local FastAPI internal webhook.
    """

    def __init__(
        self,
        endpoint_url: str = "http://127.0.0.1:8000/api/internal/events",
        queue_size: int = 200,
        request_timeout: float = 0.5,
    ):
        self.endpoint_url = endpoint_url
        self.queue_size = queue_size
        self.request_timeout = request_timeout
        self.queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._running = True
        self._worker_thread: Optional[threading.Thread] = None

    def _ensure_worker(self):
        if (self._worker_thread is None or not self._worker_thread.is_alive()) and self._running:
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="ctd-ipc-worker",
                daemon=True,
            )
            self._worker_thread.start()

    def stop(self):
        """Signals worker thread to stop and clean up."""
        self._running = False
        if self._worker_thread and self._worker_thread.is_alive():
            try:
                self.queue.put_nowait(None)
                self._worker_thread.join(timeout=0.3)
            except Exception:
                pass

    def _worker_loop(self):
        while self._running:
            try:
                event = self.queue.get(timeout=0.2)
                if event is None:
                    break
                self._dispatch_http(event)
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as exc:
                logger.debug(f"[IPC] Unexpected error in worker loop: {exc}")

    def _dispatch_http(self, event: Dict[str, Any]):
        """POST event payload to local loopback webhook."""
        try:
            payload = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                self.endpoint_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.request_timeout) as resp:
                _ = resp.read()
        except urllib.error.URLError:
            # Expected when FastAPI is not yet running or during restarts
            pass
        except Exception as exc:
            logger.debug(f"[IPC] Failed to dispatch event to {self.endpoint_url}: {exc}")

    def publish_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        window_timestamp: Optional[float] = None,
    ):
        """
        Enqueue an event for asynchronous non-blocking dispatch.
        If the queue is full, drop the event (drop-tail) to prevent backpressure.
        """
        event = {
            "event_type": event_type,
            "published_at": time.time(),
            "window_timestamp": window_timestamp or time.time(),
            "data": data,
        }
        self._ensure_worker()
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            # Drop event silently when queue is full to preserve collector performance
            logger.debug(f"[IPC] Queue full. Dropping event {event_type}")

    def publish_telemetry_window(self, metrics: Dict[str, Any]):
        """Publish completed 1-second telemetry window metrics."""
        self.publish_event(
            event_type="TELEMETRY_WINDOW",
            data=metrics,
            window_timestamp=metrics.get("timestamp"),
        )

    def publish_alert_created(self, alert_dict: Dict[str, Any]):
        """Publish new alert creation lifecycle event."""
        self.publish_event(
            event_type="ALERT_CREATED",
            data=alert_dict,
            window_timestamp=alert_dict.get("timestamp"),
        )

    def publish_alert_updated(self, alert_dict: Dict[str, Any]):
        """Publish alert update lifecycle event (e.g., event count increment)."""
        self.publish_event(
            event_type="ALERT_UPDATED",
            data=alert_dict,
            window_timestamp=alert_dict.get("last_seen"),
        )

    def publish_alert_resolved(self, alert_dict: Dict[str, Any]):
        """Publish alert resolution lifecycle event."""
        self.publish_event(
            event_type="ALERT_RESOLVED",
            data=alert_dict,
            window_timestamp=alert_dict.get("last_seen"),
        )


# Global singleton instance for use by collector and alert manager
ipc_client = LocalIPCClient()
