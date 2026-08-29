"""
CTD — Beacon Tracker

Tracks how often each (source, destination) pair starts a
NEW connection, over a longer rolling window than the
1-second / 10-second windows used elsewhere in this
project.

Botnet C2 malware "checks in" with its controller at
regular intervals (e.g. every 60 seconds). This tracker
collects those check-in timestamps so a detector can look
for suspiciously REGULAR timing.

Only connection START times are recorded here (not every
packet), because beaconing is about how OFTEN a device
starts talking to somewhere, not how much it says each
time.
"""

import statistics
from collections import defaultdict, deque


class BeaconTracker:

    def __init__(self, window_seconds: float = 300.0):

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than 0"
            )

        self.window_seconds = window_seconds

        # (src_ip, dst_ip) -> deque of connection start timestamps
        self.connections = defaultdict(deque)

    def record_new_flow(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str
    ):
        """
        Call this once, when a brand-new flow/connection
        begins (not for every packet).
        """

        key = (src_ip, dst_ip)

        self.connections[key].append(timestamp)

        self._expire(key, timestamp)

    def _expire(self, key, current_timestamp: float):

        cutoff = current_timestamp - self.window_seconds

        timestamps = self.connections[key]

        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

    def get_features(self, current_timestamp: float):
        """
        For every source IP currently being tracked, find
        the destination it has repeatedly contacted the
        MOST, and summarize how regular that timing is.
        """

        # Expire old entries and drop empty pairs.
        for key in list(self.connections.keys()):

            self._expire(key, current_timestamp)

            if not self.connections[key]:
                del self.connections[key]

        # Find each source's most-repeated destination.
        per_source_best = {}

        # Count how many DIFFERENT destinations each source
        # has repeatedly (2+ times) contacted -- used to
        # check "a small set of destinations".
        repeated_destination_counts = defaultdict(int)

        for (src_ip, dst_ip), timestamps in self.connections.items():

            count = len(timestamps)

            if count < 2:
                continue

            repeated_destination_counts[src_ip] += 1

            existing = per_source_best.get(src_ip)

            if existing is None or count > existing["count"]:

                per_source_best[src_ip] = {
                    "dst_ip": dst_ip,
                    "count": count,
                    "timestamps": list(timestamps),
                }

        results = {}

        for src_ip, info in per_source_best.items():

            timestamps = sorted(info["timestamps"])

            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]

            mean_interval = statistics.mean(intervals)

            if len(intervals) >= 2 and mean_interval > 0:

                stdev_interval = statistics.stdev(intervals)
                interval_cv = stdev_interval / mean_interval

            else:
                # Not enough data points yet to judge
                # regularity -- treat as "not regular".
                interval_cv = 1.0

            results[src_ip] = {
                "beacon_connection_count": info["count"],
                "beacon_mean_interval": mean_interval,
                "beacon_interval_cv": interval_cv,
                "beacon_repeated_destinations": (
                    repeated_destination_counts[src_ip]
                ),
            }

        return results

    def reset(self):
        self.connections.clear()
