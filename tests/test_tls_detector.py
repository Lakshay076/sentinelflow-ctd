"""
CTD — Advanced TLS, JA4, JA3S, QUIC, and SPLT Metadata Detector Tests

Tests:
1. TLS ClientHello parsing and JA3 calculation.
2. TLS ServerHello parsing and JA3S calculation.
3. Standards-compliant FoxIO JA4 fingerprint extraction.
4. Supported QUIC/HTTP3 Long Header metadata (RFC 9000).
5. Unsupported / incomplete / Short Header QUIC packets (no fabrication).
6. Packet-size and timing sequence (SPLT) extraction and behavioural anomaly detection.
7. Missing or incomplete metadata — graceful degradation without exceptions.
8. Rolling window expiration & bounded memory.
9. Existing TLS detector regression (browser-like vs minimal client).
10. DetectorEngine pipeline integration.
"""

import unittest
import hashlib
from features.tls_parser import (
    parse_client_hello,
    parse_server_hello,
    compute_ja3,
    compute_ja3s,
    compute_ja4,
    parse_quic_packet,
)
from features.tls_tracker import TLSTracker
from detectors.tls_detector import detect_tls_anomaly
from features.feature_context import FeatureContext
from detectors.detector_engine import DetectorEngine


class TestTLSDetector(unittest.TestCase):

    def _build_synthetic_client_hello(
        self,
        tls_version=0x0303,
        ciphers=None,
        extensions=None,
        sni="example.com",
        supported_versions=None,
        alpn=None,
        sig_algs=None,
    ) -> bytes:
        """Construct well-formed TLS ClientHello packet bytes."""
        if ciphers is None:
            ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f]
        if extensions is None:
            extensions = [0, 10, 11, 13, 16, 43]

        # Ciphers payload
        cipher_bytes = b"".join(int(c).to_bytes(2, "big") for c in ciphers)
        cipher_len = len(cipher_bytes).to_bytes(2, "big")

        # Extensions payload
        ext_bytes_list = []

        # SNI (ext 0)
        if 0 in extensions and sni:
            sni_ascii = sni.encode("ascii")
            sni_data = (
                int(len(sni_ascii) + 3).to_bytes(2, "big")
                + b"\x00"  # host_name type
                + int(len(sni_ascii)).to_bytes(2, "big")
                + sni_ascii
            )
            ext_bytes_list.append(b"\x00\x00" + int(len(sni_data)).to_bytes(2, "big") + sni_data)

        # Supported groups (ext 10)
        if 10 in extensions:
            curves = [0x001d, 0x0017, 0x0018]
            c_bytes = b"".join(int(c).to_bytes(2, "big") for c in curves)
            curves_data = int(len(c_bytes)).to_bytes(2, "big") + c_bytes
            ext_bytes_list.append(b"\x00\x0a" + int(len(curves_data)).to_bytes(2, "big") + curves_data)

        # EC point formats (ext 11)
        if 11 in extensions:
            ec_data = b"\x01\x00"  # 1 format: uncompressed (0)
            ext_bytes_list.append(b"\x00\x0b\x00\x02" + ec_data)

        # Signature algorithms (ext 13)
        if 13 in extensions:
            if sig_algs is None:
                sig_algs = [0x0403, 0x0804, 0x0401]
            s_bytes = b"".join(int(s).to_bytes(2, "big") for s in sig_algs)
            sig_data = int(len(s_bytes)).to_bytes(2, "big") + s_bytes
            ext_bytes_list.append(b"\x00\x0d" + int(len(sig_data)).to_bytes(2, "big") + sig_data)

        # ALPN (ext 16)
        if 16 in extensions:
            if alpn is None:
                alpn = ["h2", "http/1.1"]
            proto_bytes = b"".join(len(p).to_bytes(1, "big") + p.encode("ascii") for p in alpn)
            alpn_data = int(len(proto_bytes)).to_bytes(2, "big") + proto_bytes
            ext_bytes_list.append(b"\x00\x10" + int(len(alpn_data)).to_bytes(2, "big") + alpn_data)

        # Supported versions (ext 43)
        if 43 in extensions:
            if supported_versions is None:
                supported_versions = [0x0304, 0x0303]
            v_bytes = b"".join(int(v).to_bytes(2, "big") for v in supported_versions)
            v_data = int(len(v_bytes)).to_bytes(1, "big") + v_bytes
            ext_bytes_list.append(b"\x00\x2b" + int(len(v_data)).to_bytes(2, "big") + v_data)

        all_ext_bytes = b"".join(ext_bytes_list)
        ext_len_bytes = len(all_ext_bytes).to_bytes(2, "big")

        # Handshake body
        client_random = b"\x11" * 32
        session_id = b"\x00"  # length 0
        comp_methods = b"\x01\x00"  # 1 method: null (0)

        handshake_body = (
            int(tls_version).to_bytes(2, "big")
            + client_random
            + session_id
            + cipher_len
            + cipher_bytes
            + comp_methods
            + ext_len_bytes
            + all_ext_bytes
        )

        handshake_header = b"\x01" + int(len(handshake_body)).to_bytes(3, "big")
        record_header = b"\x16\x03\x01" + int(len(handshake_header) + len(handshake_body)).to_bytes(2, "big")

        return record_header + handshake_header + handshake_body

    def _build_synthetic_server_hello(
        self,
        server_version=0x0303,
        selected_cipher=0xc02f,
        extensions=None,
        selected_version=None,
    ) -> bytes:
        """Construct well-formed TLS ServerHello packet bytes."""
        if extensions is None:
            extensions = [0x000b, 0x0023]  # ec_points, session_ticket

        ext_bytes_list = []
        if 0x000b in extensions:
            ext_bytes_list.append(b"\x00\x0b\x00\x02\x01\x00")
        if 0x0023 in extensions:
            ext_bytes_list.append(b"\x00\x23\x00\x00")
        if selected_version is not None:
            # supported_versions (ext 43) in ServerHello carries selected version
            v_data = int(selected_version).to_bytes(2, "big")
            ext_bytes_list.append(b"\x00\x2b\x00\x02" + v_data)
            extensions.append(43)

        all_ext_bytes = b"".join(ext_bytes_list)
        ext_len_bytes = len(all_ext_bytes).to_bytes(2, "big")

        server_random = b"\x22" * 32
        session_id = b"\x00"  # length 0
        cipher_bytes = int(selected_cipher).to_bytes(2, "big")
        comp_method = b"\x00"  # null

        handshake_body = (
            int(server_version).to_bytes(2, "big")
            + server_random
            + session_id
            + cipher_bytes
            + comp_method
            + ext_len_bytes
            + all_ext_bytes
        )

        handshake_header = b"\x02" + int(len(handshake_body)).to_bytes(3, "big")
        record_header = b"\x16\x03\x03" + int(len(handshake_header) + len(handshake_body)).to_bytes(2, "big")

        return record_header + handshake_header + handshake_body

    def test_client_hello_parsing_and_ja3(self):
        """Verify TLS ClientHello parser extracts fields and computes JA3 correctly."""
        raw = self._build_synthetic_client_hello(
            tls_version=0x0303,
            ciphers=[0x1301, 0x1302, 0xc02b],
            extensions=[0, 10, 11],
            sni="test.example.com",
        )
        parsed = parse_client_hello(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["tls_version"], 0x0303)
        self.assertEqual(parsed["sni"], "test.example.com")
        self.assertEqual(parsed["cipher_suites"], [0x1301, 0x1302, 0xc02b])
        self.assertEqual(parsed["extensions"], [0, 10, 11])

        ja3_str, ja3_hash = compute_ja3(parsed)
        self.assertTrue(ja3_str.startswith("771,4865-4866-49195,0-10-11"))
        self.assertEqual(len(ja3_hash), 32)

    def test_server_hello_parsing_and_ja3s(self):
        """Verify TLS ServerHello parser extracts selected cipher and computes JA3S correctly."""
        raw = self._build_synthetic_server_hello(
            server_version=0x0303,
            selected_cipher=0xc02f,
            extensions=[0x000b, 0x0023],
        )
        parsed = parse_server_hello(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["tls_version"], 0x0303)
        self.assertEqual(parsed["selected_cipher"], 0xc02f)
        self.assertEqual(parsed["extensions"], [11, 35])

        ja3s_str, ja3s_hash = compute_ja3s(parsed)
        self.assertEqual(ja3s_str, "771,49199,11-35")
        self.assertEqual(len(ja3s_hash), 32)
        expected_hash = hashlib.md5(b"771,49199,11-35").hexdigest()
        self.assertEqual(ja3s_hash, expected_hash)

    def test_ja4_fingerprinting_specification(self):
        """Verify standards-compliant FoxIO JA4 fingerprint structure (JA4_a_JA4_b_JA4_c)."""
        raw = self._build_synthetic_client_hello(
            tls_version=0x0303,
            ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            extensions=[0, 10, 11, 13, 16, 43],
            sni="api.target.com",
            supported_versions=[0x0304, 0x0303],
            alpn=["h2", "http/1.1"],
            sig_algs=[0x0403, 0x0804, 0x0401],
        )
        parsed = parse_client_hello(raw)
        ja4_full, ja4_b = compute_ja4(parsed, protocol="t")

        parts = ja4_full.split("_")
        self.assertEqual(len(parts), 3, "JA4 must have exactly 3 parts separated by underscores")

        ja4_a, ja4_b_part, ja4_c = parts
        self.assertEqual(len(ja4_a), 10, "JA4 Section A must be exactly 10 characters")
        self.assertEqual(len(ja4_b_part), 12, "JA4 Section B must be exactly 12 hex characters")
        self.assertEqual(len(ja4_c), 12, "JA4 Section C must be exactly 12 hex characters")

        # Section A validation: t + 13 + d + 05 + 06 + h2
        self.assertEqual(ja4_a[0], "t", "Protocol must be 't' for TCP")
        self.assertEqual(ja4_a[1:3], "13", "Highest supported version 0x0304 must map to '13'")
        self.assertEqual(ja4_a[3], "d", "Domain SNI must produce 'd'")
        self.assertEqual(ja4_a[4:6], "05", "5 ciphers must produce '05'")
        self.assertEqual(ja4_a[6:8], "06", "6 extensions must produce '06'")
        self.assertEqual(ja4_a[8:10], "h2", "ALPN 'h2' must produce 'h2'")

        # Missing SNI produces 'i'
        raw_no_sni = self._build_synthetic_client_hello(sni=None)
        parsed_no_sni = parse_client_hello(raw_no_sni)
        ja4_no_sni, _ = compute_ja4(parsed_no_sni, protocol="t")
        self.assertEqual(ja4_no_sni.split("_")[0][3], "i")

        # QUIC protocol produces 'q'
        ja4_quic, _ = compute_ja4(parsed, protocol="q")
        self.assertTrue(ja4_quic.startswith("q13d"))

    def test_quic_metadata_extraction_supported(self):
        """Passively parse observable Long Header QUIC Initial packet (RFC 9000)."""
        # Long Header (0xc0 = Initial, Fixed bit=1), Version 1, DCIL=4, DCID, SCIL=4, SCID
        quic_bytes = (
            b"\xc0"                  # Long Header, Initial
            + b"\x00\x00\x00\x01"    # QUIC Version 1 (RFC 9000)
            + b"\x04"                # DCIL = 4
            + b"\xaa\xbb\xcc\xdd"    # DCID
            + b"\x04"                # SCIL = 4
            + b"\x11\x22\x33\x44"    # SCID
            + b"\x00"                # Token length = 0
            + b"\x05"                # Length
            + b"\x00\x01\x02\x03\x04" # Payload
        )
        meta = parse_quic_packet(quic_bytes)
        self.assertIsNotNone(meta)
        self.assertTrue(meta["is_quic"])
        self.assertEqual(meta["header_type"], "LONG")
        self.assertEqual(meta["packet_type"], "INITIAL")
        self.assertEqual(meta["version"], 1)
        self.assertEqual(meta["version_hex"], "0x00000001")
        self.assertEqual(meta["version_name"], "QUICv1 (RFC 9000)")
        self.assertEqual(meta["dcid"], "aabbccdd")
        self.assertEqual(meta["scid"], "11223344")

    def test_quic_metadata_unsupported_or_incomplete(self):
        """Truncated or invalid QUIC packets must degrade safely without fabricating fields."""
        # Truncated
        self.assertIsNone(parse_quic_packet(b"\xc0\x00\x00"))

        # Short Header packet (0x40 = 1-RTT encrypted application data)
        short_bytes = b"\x40\x11\x22\x33\x44\x55"
        meta = parse_quic_packet(short_bytes)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["header_type"], "SHORT")
        self.assertEqual(meta["packet_type"], "1-RTT")
        self.assertIsNone(meta["client_hello"], "Encrypted 1-RTT must not fabricate ClientHello")
        self.assertIsNone(meta["ja4"], "Encrypted 1-RTT must not fabricate JA4")

    def test_splt_sequence_and_timing_extraction(self):
        """Verify SPLT (Sequence of Packet Length and Time) captures packet sizes and timing jitter."""
        tracker = TLSTracker(window_seconds=300.0)

        # Simulate 10 packets with robotic fixed 1.0s intervals and 500-byte sizes
        t = 1000.0
        for _ in range(10):
            tracker.add_splt_packet(timestamp=t, src_ip="10.0.0.88", packet_bytes=500)
            t += 1.0

        features = tracker.get_features(current_timestamp=t)["10.0.0.88"]
        self.assertEqual(features["splt_packet_count"], 10)
        self.assertEqual(features["splt_mean_length"], 500.0)
        self.assertEqual(features["splt_length_stdev"], 0.0)
        self.assertAlmostEqual(features["splt_mean_ipt"], 1000.0, places=1)
        self.assertLess(features["splt_ipt_cv"], 0.05, "Fixed interval timing must produce low CV")

        # Test detector flags this robotic encrypted timing
        result = detect_tls_anomaly(features)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, "TLS_METADATA_ANOMALY")
        reasons_text = " ".join(result.reasons)
        self.assertIn("robotic encrypted traffic timing", reasons_text.lower())

    def test_missing_metadata_graceful_degradation(self):
        """Empty or incomplete feature dictionaries degrade gracefully with zero exceptions."""
        result_empty = detect_tls_anomaly({})
        self.assertFalse(result_empty.detected)
        self.assertEqual(result_empty.severity, "NONE")
        self.assertEqual(result_empty.score, 0)
        self.assertEqual(result_empty.confidence, 0.0)

    def test_rolling_window_expiration(self):
        """Observations older than window_seconds are purged cleanly from TLSTracker."""
        tracker = TLSTracker(window_seconds=300.0)

        tracker.add_client_hello(
            timestamp=100.0,
            src_ip="10.0.0.77",
            dst_ip="1.1.1.1",
            ja3_hash="dummy-ja3",
            cipher_count=20,
            extension_count=10,
            has_sni=True,
        )
        self.assertEqual(len(tracker.hellos["10.0.0.77"]), 1)

        # Advance beyond 300s
        features_expired = tracker.get_features(current_timestamp=500.0)
        self.assertNotIn("10.0.0.77", features_expired)
        self.assertEqual(len(tracker.hellos), 0)

    def test_existing_tls_detector_regression(self):
        """Verify existing browser-like vs minimal client detection behavior is preserved."""
        # Browser client
        browser_features = {
            "tls_client_hello_count": 5,
            "tls_avg_cipher_count": 25.0,
            "tls_avg_extension_count": 12.0,
            "tls_missing_sni_ratio": 0.0,
            "tls_max_same_ja3_to_one_dest": 1,
        }
        res_browser = detect_tls_anomaly(browser_features)
        self.assertFalse(res_browser.detected, "Browser-like TLS must NOT be flagged")

        # Minimal / malware client
        malware_features = {
            "tls_client_hello_count": 6,
            "tls_avg_cipher_count": 3.0,
            "tls_avg_extension_count": 2.0,
            "tls_missing_sni_ratio": 1.0,
            "tls_max_same_ja3_to_one_dest": 6,
        }
        res_malware = detect_tls_anomaly(malware_features)
        self.assertTrue(res_malware.detected, "Minimal TLS client must be flagged")
        self.assertEqual(res_malware.severity, "HIGH")

    def test_detector_engine_pipeline_integration(self):
        """End-to-end integration: TLSTracker features pass through FeatureContext to DetectorEngine."""
        tracker = TLSTracker(window_seconds=300.0)
        engine = DetectorEngine()

        # Attacker source with repeated minimal JA4 fingerprint
        for i in range(6):
            tracker.add_client_hello(
                timestamp=10.0 + i * 50.0,
                src_ip="10.0.0.99",
                dst_ip="203.0.113.10",
                ja3_hash="c2-ja3-hash",
                cipher_count=3,
                extension_count=2,
                has_sni=False,
                ja4_hash="c2-ja4-hash",
                ja4_full="t12i030200_1301c02b_000a",
            )

        tls_features = tracker.get_features(current_timestamp=300.0)
        context = FeatureContext(
            network={},
            security={},
            sources={},
            tls=tls_features,
        )

        detections = engine.analyze_context(context)
        self.assertIn("10.0.0.99", detections)
        tls_alerts = [r for r in detections["10.0.0.99"] if r.attack_type == "TLS_METADATA_ANOMALY"]
        self.assertTrue(len(tls_alerts) >= 1)
        self.assertEqual(tls_alerts[0].severity, "HIGH")

    def test_splt_only_omits_client_hello_sentinel_and_uses_schema_default(self):
        """SPLT-only traffic without ClientHello must NOT emit tls_avg_cipher_count=999.0."""
        from inference.feature_schema import DEFAULT_VALUES, FEATURE_NAMES, features_to_vector

        tracker = TLSTracker(window_seconds=300.0)
        for i in range(4):
            tracker.add_splt_packet(timestamp=100.0 + i * 0.5, src_ip="10.0.0.17", packet_bytes=200)

        features = tracker.get_features(current_timestamp=102.0)["10.0.0.17"]
        self.assertEqual(features["tls_client_hello_count"], 0)
        self.assertNotIn("tls_avg_cipher_count", features)
        self.assertNotIn("tls_avg_extension_count", features)
        self.assertNotIn("tls_missing_sni_ratio", features)

        vec = features_to_vector(features)
        cipher_idx = FEATURE_NAMES.index("tls_avg_cipher_count")
        self.assertEqual(vec[cipher_idx], DEFAULT_VALUES["tls_avg_cipher_count"])

    def test_valid_client_hello_preserves_client_hello_features(self):
        """Valid ClientHello observations must still populate cipher/extension/SNI/JA3/JA4 features."""
        tracker = TLSTracker(window_seconds=300.0)
        tracker.add_client_hello(
            timestamp=100.0,
            src_ip="10.0.0.55",
            dst_ip="203.0.113.10",
            ja3_hash="abc123",
            cipher_count=2,
            extension_count=1,
            has_sni=False,
            ja4_hash="def456",
            ja4_full="t12i020100_def456_0000",
        )
        features = tracker.get_features(current_timestamp=101.0)["10.0.0.55"]
        self.assertEqual(features["tls_client_hello_count"], 1)
        self.assertEqual(features["tls_avg_cipher_count"], 2.0)
        self.assertEqual(features["tls_avg_extension_count"], 1.0)
        self.assertEqual(features["tls_missing_sni_ratio"], 1.0)
        self.assertEqual(features["tls_max_same_ja3_to_one_dest"], 1)
        self.assertEqual(features["tls_max_same_ja4_to_one_dest"], 1)

    def test_no_tls_observations_returns_empty_and_normal_defaults(self):
        """No TLS observations must return empty tracker map and safe ML defaults."""
        from inference.feature_schema import DEFAULT_VALUES, FEATURE_NAMES, features_to_vector

        tracker = TLSTracker(window_seconds=300.0)
        self.assertEqual(tracker.get_features(current_timestamp=100.0), {})
        vec = features_to_vector({})
        cipher_idx = FEATURE_NAMES.index("tls_avg_cipher_count")
        self.assertEqual(vec[cipher_idx], DEFAULT_VALUES["tls_avg_cipher_count"])


def main():
    print("=" * 70)
    print("CTD — TLS, JA3S, JA4, QUIC & SPLT DETECTOR TEST SUITE")
    print("=" * 70)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestTLSDetector)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)


if __name__ == "__main__":
    main()
