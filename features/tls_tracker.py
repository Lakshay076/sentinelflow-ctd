"""
CTD — TLS Metadata Tracker

Tracks TLS ClientHello metadata per source IP over a
rolling window: how many cipher suites/extensions each
connection offered, whether SNI (the requested server
name) was present, and how often the exact same
fingerprint repeats toward the same destination.

No decrypted content is ever used -- only the ClientHello
structure, which is always sent in the clear by design
(it has to be, since the server needs to read it before
encryption can even begin).
"""

from collections import defaultdict, deque


class TLSTracker:

    def __init__(self, window_seconds: float = 300.0):

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than 0"
            )

        self.window_seconds = window_seconds

        # NOTE: default is 300 seconds (5 minutes), not 60.
        # This matches BeaconTracker's window, so that
        # malware repeating a TLS handshake every ~60-90
        # seconds toward the same server (a very common C2
        # pattern) stays visible in this window long enough
        # for the repetition to actually be counted.

        # src_ip -> deque of (timestamp, dst_ip, ja3_hash,
        #                      cipher_count, extension_count,
        #                      has_sni)
        self.hellos = defaultdict(deque)

    def add_client_hello(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        ja3_hash: str,
        cipher_count: int,
        extension_count: int,
        has_sni: bool,
    ):

        entry = (
            timestamp, dst_ip, ja3_hash,
            cipher_count, extension_count, has_sni,
        )

        self.hellos[src_ip].append(entry)

        self._expire(src_ip, timestamp)

    def _expire(self, src_ip, current_timestamp: float):

        cutoff = current_timestamp - self.window_seconds

        entries = self.hellos[src_ip]

        while entries and entries[0][0] < cutoff:
            entries.popleft()

    def get_features(self, current_timestamp: float):

        for src_ip in list(self.hellos.keys()):

            self._expire(src_ip, current_timestamp)

            if not self.hellos[src_ip]:
                del self.hellos[src_ip]

        results = {}

        for src_ip, entries in self.hellos.items():

            count = len(entries)

            if count == 0:
                continue

            cipher_counts = [e[3] for e in entries]
            extension_counts = [e[4] for e in entries]
            sni_flags = [e[5] for e in entries]

            avg_cipher_count = sum(cipher_counts) / count
            avg_extension_count = sum(extension_counts) / count

            missing_sni_ratio = (
                sum(1 for flag in sni_flags if not flag) / count
            )

            # For each (destination, ja3) pair seen from this
            # source, count repeats. Take the largest -- this
            # tells us "how many times did this source present
            # the EXACT SAME fingerprint to the SAME
            # destination".
            pair_counts = defaultdict(int)

            for entry in entries:
                dst_ip = entry[1]
                ja3_hash = entry[2]
                pair_counts[(dst_ip, ja3_hash)] += 1

            max_same_ja3_to_one_dest = max(pair_counts.values())

            results[src_ip] = {
                "tls_client_hello_count": count,
                "tls_avg_cipher_count": avg_cipher_count,
                "tls_avg_extension_count": avg_extension_count,
                "tls_missing_sni_ratio": missing_sni_ratio,
                "tls_max_same_ja3_to_one_dest": (
                    max_same_ja3_to_one_dest
                ),
            }

        return results

    def reset(self):
        self.hellos.clear()
