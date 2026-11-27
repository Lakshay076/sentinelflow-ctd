"""
CTD — Advanced TLS & Encrypted-Traffic Metadata Tracker

Tracks passive, zero-decryption metadata per source IP over a rolling window:
1. TLS ClientHello & JA3/JA4 Fingerprinting:
   Cipher/extension counts, missing SNI, and repeated identical fingerprints.
2. TLS ServerHello & JA3S Fingerprinting:
   Observed server selected cipher and extension negotiation fingerprints.
3. QUIC / HTTP3 Metadata:
   Header type, connection IDs (DCID/SCID), QUIC version, and Initial handshakes.
4. SPLT (Sequence of Packet Length and Time):
   Bounded sequence of packet sizes and inter-packet arrival times (IPT)
   used for behavioural anomaly analysis of opaque encrypted flows.

No decrypted content is ever used. Passive streaming analysis only.
"""

import math
from collections import defaultdict, deque
from typing import Dict, List, Optional


MAX_TRACKED_EVENTS_PER_SOURCE: int = 300
MAX_SPLT_SEQUENCE_LENGTH: int = 50


class TLSTracker:

    def __init__(self, window_seconds: float = 300.0):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than 0")

        self.window_seconds = window_seconds

        # src_ip -> deque of ClientHello records
        self.hellos = defaultdict(lambda: deque(maxlen=MAX_TRACKED_EVENTS_PER_SOURCE))

        # server_ip -> deque of ServerHello records (JA3S)
        self.server_hellos = defaultdict(lambda: deque(maxlen=MAX_TRACKED_EVENTS_PER_SOURCE))

        # src_ip -> deque of QUIC packet records
        self.quic_packets = defaultdict(lambda: deque(maxlen=MAX_TRACKED_EVENTS_PER_SOURCE))

        # src_ip -> deque of SPLT tuples (timestamp, packet_bytes)
        self.splt_sequences = defaultdict(lambda: deque(maxlen=MAX_SPLT_SEQUENCE_LENGTH))

    def add_client_hello(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        ja3_hash: str,
        cipher_count: int,
        extension_count: int,
        has_sni: bool,
        ja4_hash: Optional[str] = None,
        ja4_full: Optional[str] = None,
    ):
        """Record an observed TLS ClientHello for a source IP."""
        entry = {
            "timestamp": timestamp,
            "dst_ip": dst_ip,
            "ja3_hash": ja3_hash,
            "cipher_count": cipher_count,
            "extension_count": extension_count,
            "has_sni": has_sni,
            "ja4_hash": ja4_hash or "",
            "ja4_full": ja4_full or "",
        }
        self.hellos[src_ip].append(entry)
        self._expire(src_ip, timestamp)

    def add_server_hello(
        self,
        timestamp: float,
        server_ip: str,
        client_ip: str,
        ja3s_hash: str,
        cipher_suite: int,
        extension_count: int,
    ):
        """Record an observed TLS ServerHello for a server IP."""
        entry = {
            "timestamp": timestamp,
            "client_ip": client_ip,
            "ja3s_hash": ja3s_hash,
            "cipher_suite": cipher_suite,
            "extension_count": extension_count,
        }
        self.server_hellos[server_ip].append(entry)
        self._expire(server_ip, timestamp)

    def add_quic_packet(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        quic_meta: dict,
        packet_bytes: int = 0,
    ):
        """Record an observed QUIC/HTTP3 packet for a source IP."""
        entry = {
            "timestamp": timestamp,
            "dst_ip": dst_ip,
            "header_type": quic_meta.get("header_type", "UNKNOWN"),
            "packet_type": quic_meta.get("packet_type", "UNKNOWN"),
            "version_hex": quic_meta.get("version_hex"),
            "dcid": quic_meta.get("dcid"),
            "scid": quic_meta.get("scid"),
            "ja4": quic_meta.get("ja4"),
            "packet_bytes": packet_bytes,
        }
        self.quic_packets[src_ip].append(entry)
        self._expire(src_ip, timestamp)

    def add_splt_packet(
        self,
        timestamp: float,
        src_ip: str,
        packet_bytes: int,
    ):
        """Record packet length and arrival time for SPLT sequence analysis."""
        if packet_bytes > 0:
            self.splt_sequences[src_ip].append((timestamp, packet_bytes))
            self._expire(src_ip, timestamp)

    def _expire(self, src_ip: str, current_timestamp: float):
        """Purge observations older than the rolling window duration."""
        cutoff = current_timestamp - self.window_seconds

        hellos = self.hellos[src_ip]
        while hellos and hellos[0]["timestamp"] < cutoff:
            hellos.popleft()

        s_hellos = self.server_hellos[src_ip]
        while s_hellos and s_hellos[0]["timestamp"] < cutoff:
            s_hellos.popleft()

        quic = self.quic_packets[src_ip]
        while quic and quic[0]["timestamp"] < cutoff:
            quic.popleft()

        splt = self.splt_sequences[src_ip]
        while splt and splt[0][0] < cutoff:
            splt.popleft()

    def get_features(self, current_timestamp: float) -> Dict[str, Dict]:
        """
        Calculate TLS, JA4, QUIC, and SPLT features for every active source IP.
        """
        all_sources = (
            set(self.hellos.keys())
            | set(self.server_hellos.keys())
            | set(self.quic_packets.keys())
            | set(self.splt_sequences.keys())
        )

        for src_ip in list(all_sources):
            self._expire(src_ip, current_timestamp)
            if (
                not self.hellos[src_ip]
                and not self.server_hellos[src_ip]
                and not self.quic_packets[src_ip]
                and not self.splt_sequences[src_ip]
            ):
                self.hellos.pop(src_ip, None)
                self.server_hellos.pop(src_ip, None)
                self.quic_packets.pop(src_ip, None)
                self.splt_sequences.pop(src_ip, None)

        active_ips = (
            set(self.hellos.keys())
            | set(self.server_hellos.keys())
            | set(self.quic_packets.keys())
            | set(self.splt_sequences.keys())
        )

        results = {}

        for src_ip in active_ips:
            entries = self.hellos.get(src_ip, [])
            count = len(entries)

            # ---------------------------------------------------------
            # 1. Existing TLS ClientHello & JA3 Features (100% Preserved)
            # ---------------------------------------------------------
            if count > 0:
                cipher_counts = [e["cipher_count"] for e in entries]
                extension_counts = [e["extension_count"] for e in entries]
                sni_flags = [e["has_sni"] for e in entries]

                avg_cipher_count = sum(cipher_counts) / count
                avg_extension_count = sum(extension_counts) / count
                missing_sni_ratio = sum(1 for flag in sni_flags if not flag) / count

                pair_counts = defaultdict(int)
                ja4_pair_counts = defaultdict(int)
                unique_ja3s = set()
                unique_ja4s = set()
                latest_ja4 = ""

                for entry in entries:
                    dst_ip = entry["dst_ip"]
                    ja3_h = entry["ja3_hash"]
                    ja4_h = entry["ja4_hash"]
                    ja4_f = entry["ja4_full"]

                    pair_counts[(dst_ip, ja3_h)] += 1
                    if ja4_h:
                        ja4_pair_counts[(dst_ip, ja4_h)] += 1
                        unique_ja4s.add(ja4_h)
                        latest_ja4 = ja4_f

                    if ja3_h:
                        unique_ja3s.add(ja3_h)

                max_same_ja3_to_one_dest = max(pair_counts.values()) if pair_counts else 0
                max_same_ja4_to_one_dest = max(ja4_pair_counts.values()) if ja4_pair_counts else 0
                unique_ja3_count = len(unique_ja3s)
                unique_ja4_count = len(unique_ja4s)

            else:
                # No ClientHello was observed. This is "not observed",
                # not an extremely small cipher-suite offer.
                avg_cipher_count = 20.0
                avg_extension_count = 20.0
                missing_sni_ratio = 0.0
                max_same_ja3_to_one_dest = 0
                max_same_ja4_to_one_dest = 0
                unique_ja3_count = 0
                unique_ja4_count = 0
                latest_ja4 = ""

            # ---------------------------------------------------------
            # 2. ServerHello & JA3S Features
            # ---------------------------------------------------------
            s_entries = self.server_hellos.get(src_ip, [])
            ja3s_count = len(s_entries)
            unique_ja3s = len(set(e["ja3s_hash"] for e in s_entries))

            # ---------------------------------------------------------
            # 3. QUIC / HTTP3 Metadata Features
            # ---------------------------------------------------------
            q_entries = self.quic_packets.get(src_ip, [])
            quic_packet_count = len(q_entries)
            quic_active = quic_packet_count > 0
            quic_initial_count = sum(1 for q in q_entries if q["packet_type"] == "INITIAL")
            quic_version = q_entries[-1]["version_hex"] if q_entries and q_entries[-1]["version_hex"] else ""

            # ---------------------------------------------------------
            # 4. SPLT (Sequence of Packet Length and Time) Features
            # ---------------------------------------------------------
            splt_entries = self.splt_sequences.get(src_ip, [])
            splt_count = len(splt_entries)

            if splt_count >= 2:
                lengths = [p[1] for p in splt_entries]
                times = [p[0] for p in splt_entries]

                splt_mean_length = sum(lengths) / splt_count
                variance_len = sum((l - splt_mean_length) ** 2 for l in lengths) / splt_count
                splt_length_stdev = math.sqrt(variance_len)

                ipts = [(times[i] - times[i - 1]) * 1000.0 for i in range(1, len(times))]
                splt_mean_ipt = sum(ipts) / len(ipts) if ipts else 0.0
                variance_ipt = (
                    sum((t - splt_mean_ipt) ** 2 for t in ipts) / len(ipts)
                    if ipts
                    else 0.0
                )
                splt_ipt_stdev = math.sqrt(variance_ipt)
                splt_ipt_cv = (
                    splt_ipt_stdev / max(splt_mean_ipt, 0.001)
                    if splt_mean_ipt > 0
                    else 1.0
                )
                splt_sample_sequence = lengths[:10]
            else:
                splt_mean_length = 0.0
                splt_length_stdev = 0.0
                splt_mean_ipt = 0.0
                splt_ipt_stdev = 0.0
                splt_ipt_cv = 1.0
                splt_sample_sequence = []

            results[src_ip] = {
                # Existing Features (Preserved 100%)
                "tls_client_hello_count": count,
                "tls_avg_cipher_count": avg_cipher_count,
                "tls_avg_extension_count": avg_extension_count,
                "tls_missing_sni_ratio": missing_sni_ratio,
                "tls_max_same_ja3_to_one_dest": max_same_ja3_to_one_dest,

                # JA4 Features
                "tls_unique_ja4_count": unique_ja4_count,
                "tls_latest_ja4": latest_ja4,
                "tls_max_same_ja4_to_one_dest": max_same_ja4_to_one_dest,

                # JA3S Features
                "tls_ja3s_count": ja3s_count,
                "tls_unique_ja3s_count": unique_ja3s,

                # QUIC / HTTP3 Features
                "quic_packet_count": quic_packet_count,
                "quic_active": quic_active,
                "quic_version": quic_version,
                "quic_initial_count": quic_initial_count,

                # SPLT Sequence Features
                "splt_packet_count": splt_count,
                "splt_mean_length": splt_mean_length,
                "splt_length_stdev": splt_length_stdev,
                "splt_mean_ipt": splt_mean_ipt,
                "splt_ipt_cv": splt_ipt_cv,
                "splt_sample_sequence": splt_sample_sequence,
            }

        return results

    def reset(self):
        """Clear all stored TLS, QUIC, and SPLT state."""
        self.hellos.clear()
        self.server_hellos.clear()
        self.quic_packets.clear()
        self.splt_sequences.clear()
