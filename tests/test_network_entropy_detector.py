"""
Unit & Integration Tests for Network-Wide Source IP Entropy & Distributed UDP Flood Detector

Covers:
1. Normal traffic from a small number of sources (benign / zero false positive).
2. Distributed UDP traffic from many sources (detected, severity HIGH, confidence 1.0).
3. High entropy but low traffic volume (safely ignored, no false positive).
4. High traffic from one source (not flagged as distributed; handled by single-source detector).
5. Insufficient samples / empty features (graceful degradation, zero crash).
6. Window expiration and reset (WindowManager rolling reset cleans state).
7. Non-regression of existing UDP flood and SYN flood detectors.
8. DetectorEngine context analysis and AlertManager lifecycle on __NETWORK__.
"""

import unittest
from detectors.network_entropy_detector import (
    detect_distributed_udp_flood,
    calculate_shannon_entropy,
    MIN_AGGREGATE_UDP_PACKETS,
    MIN_AGGREGATE_UDP_RATE,
    MIN_UNIQUE_SOURCES,
    MIN_NORMALIZED_SOURCE_ENTROPY,
)
from detectors.udp_flood_detector import detect_udp_flood
from detectors.syn_flood_detector import detect_syn_flood
from detectors.detector_engine import DetectorEngine
from features.window import ObservationWindow, WindowManager
from features.feature_context import FeatureContext
from alerts.alert_manager import AlertManager


class TestNetworkEntropyDetector(unittest.TestCase):

    def test_shannon_entropy_calculation(self):
        """Verify mathematical correctness of Shannon entropy calculation."""
        # Single source: entropy should be 0.0
        h_single, norm_single = calculate_shannon_entropy({"10.0.0.1": 100})
        self.assertEqual(h_single, 0.0)
        self.assertEqual(norm_single, 0.0)

        # Equal distribution across 4 sources: H = log2(4) = 2.0 bits, norm = 1.0
        counts_4 = {"10.0.0.1": 25, "10.0.0.2": 25, "10.0.0.3": 25, "10.0.0.4": 25}
        h_4, norm_4 = calculate_shannon_entropy(counts_4)
        self.assertAlmostEqual(h_4, 2.0, places=4)
        self.assertAlmostEqual(norm_4, 1.0, places=4)

        # Heavily skewed distribution (1 source dominant, 9 tiny): low normalized entropy
        skewed = {"10.0.0.1": 990}
        for i in range(2, 11):
            skewed[f"10.0.0.{i}"] = 1
        h_skewed, norm_skewed = calculate_shannon_entropy(skewed)
        self.assertLess(norm_skewed, 0.20, "Skewed distribution must yield low normalized entropy")

    def test_normal_traffic_few_sources(self):
        """Normal traffic from a small number of legitimate sources must not trigger."""
        features = {
            "packets": 50,
            "udp_packets": 20,
            "bytes": 10_000,
            "udp_bytes": 4_000,
            "udp_rate": 20.0,
            "udp_bytes_per_second": 4_000.0,
            "unique_sources": 3,
            "source_ip_entropy": 1.45,
            "normalized_source_entropy": 0.91,
            "mean_packets_per_source": 6.67,
            "udp_packet_ratio": 0.40,
            "window_duration": 1.0,
        }
        result = detect_distributed_udp_flood(features)
        self.assertFalse(result.detected, "Normal small-source traffic should not trigger")
        self.assertEqual(result.severity, "NONE")
        self.assertEqual(result.attack_type, None)

    def test_distributed_udp_traffic_many_sources(self):
        """Distributed UDP flood from many spoofed sources must trigger HIGH severity alert."""
        # 300 packets across 50 spoofed source IPs (6 pkts/source)
        source_counts = {f"10.99.0.{i}": 6 for i in range(50)}
        h_bits, h_norm = calculate_shannon_entropy(source_counts)

        features = {
            "packets": 300,
            "udp_packets": 300,
            "bytes": 150_000,
            "udp_bytes": 150_000,
            "udp_rate": 300.0,
            "udp_bytes_per_second": 150_000.0,
            "unique_sources": 50,
            "source_ip_entropy": h_bits,
            "normalized_source_entropy": h_norm,
            "mean_packets_per_source": 6.0,
            "udp_packet_ratio": 1.0,
            "window_duration": 1.0,
        }
        result = detect_distributed_udp_flood(features)
        self.assertTrue(result.detected, "Distributed spoofed UDP flood must be detected")
        self.assertEqual(result.attack_type, "DISTRIBUTED_UDP_FLOOD")
        self.assertEqual(result.severity, "HIGH")
        self.assertGreaterEqual(result.confidence, 0.80)
        self.assertGreaterEqual(result.score, 4)
        reasons_str = " ".join(result.reasons)
        self.assertIn("entropy", reasons_str.lower())
        self.assertIn("dispersed", reasons_str.lower())

    def test_high_entropy_low_traffic(self):
        """High entropy with low traffic volume (e.g. 15 DNS lookups from 15 hosts) must NOT trigger."""
        features = {
            "packets": 15,
            "udp_packets": 15,
            "bytes": 1_200,
            "udp_bytes": 1_200,
            "udp_rate": 15.0,
            "udp_bytes_per_second": 1_200.0,
            "unique_sources": 15,
            "source_ip_entropy": 3.90,
            "normalized_source_entropy": 1.0,
            "mean_packets_per_source": 1.0,
            "udp_packet_ratio": 1.0,
            "window_duration": 1.0,
        }
        result = detect_distributed_udp_flood(features)
        self.assertFalse(result.detected, "High entropy without volumetric traffic must not trigger")
        self.assertEqual(result.severity, "NONE")

    def test_high_traffic_one_source(self):
        """High traffic from one source must NOT trigger distributed detector (entropy is 0)."""
        features = {
            "packets": 600,
            "udp_packets": 600,
            "bytes": 300_000,
            "udp_bytes": 300_000,
            "udp_rate": 600.0,
            "udp_bytes_per_second": 300_000.0,
            "unique_sources": 1,
            "source_ip_entropy": 0.0,
            "normalized_source_entropy": 0.0,
            "mean_packets_per_source": 600.0,
            "udp_packet_ratio": 1.0,
            "window_duration": 1.0,
        }
        result_distributed = detect_distributed_udp_flood(features)
        self.assertFalse(result_distributed.detected, "Single source flood must not trigger distributed detector")

        # But per-source detector DOES detect it!
        result_single = detect_udp_flood(features)
        self.assertTrue(result_single.detected, "Single source detector must catch concentrated flood")
        self.assertEqual(result_single.attack_type, "UDP_FLOOD")

    def test_insufficient_samples(self):
        """Insufficient samples or empty features must degrade safely with zero exception."""
        res_empty = detect_distributed_udp_flood({})
        self.assertFalse(res_empty.detected)
        self.assertEqual(res_empty.severity, "NONE")
        self.assertEqual(res_empty.score, 0)
        self.assertEqual(res_empty.confidence, 0.0)

        res_zero_udp = detect_distributed_udp_flood({"udp_packets": 0, "packets": 200, "unique_sources": 20})
        self.assertFalse(res_zero_udp.detected)

    def test_window_expiration_and_reset(self):
        """Verify ObservationWindow properly computes entropy and WindowManager resets state across windows."""
        wm = WindowManager(window_seconds=1.0)

        # Window 1: Inject distributed attack (t=100.0 to 100.9s)
        for i in range(40):
            wm.add_packet(
                timestamp=100.0 + (i * 0.02),
                src_ip=f"192.168.1.{i+1}",
                dst_ip="10.0.0.1",
                protocol="UDP",
                packet_bytes=100,
                dst_port=53,
            )

        # Closing packet at t=101.1 closes Window 1 and returns its features
        win1_features = wm.add_packet(
            timestamp=101.1,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            protocol="TCP",
            packet_bytes=60,
        )

        self.assertIsNotNone(win1_features)
        self.assertEqual(win1_features["unique_sources"], 40)
        self.assertEqual(win1_features["udp_packets"], 40)
        self.assertGreaterEqual(win1_features["source_ip_entropy"], 5.0)
        self.assertGreaterEqual(win1_features["normalized_source_entropy"], 0.95)

        # Window 1 detected as distributed attack
        res_win1 = detect_distributed_udp_flood(win1_features)
        self.assertTrue(res_win1.detected)
        self.assertEqual(res_win1.attack_type, "DISTRIBUTED_UDP_FLOOD")

        # Window 2: Only 1 benign packet arrived. Next boundary closes Window 2.
        win2_features = wm.add_packet(
            timestamp=102.2,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            protocol="TCP",
            packet_bytes=60,
        )
        self.assertIsNotNone(win2_features)
        self.assertEqual(win2_features["udp_packets"], 0)
        self.assertEqual(win2_features["unique_sources"], 1)

        # Window 2 must NOT trigger
        res_win2 = detect_distributed_udp_flood(win2_features)
        self.assertFalse(res_win2.detected)

    def test_custom_thresholds_override(self):
        """Operators can tune thresholds via thresholds parameter."""
        features = {
            "packets": 25,
            "udp_packets": 25,
            "bytes": 20_000,
            "udp_bytes": 20_000,
            "udp_rate": 25.0,
            "udp_bytes_per_second": 20_000.0,
            "unique_sources": 8,
            "source_ip_entropy": 2.9,
            "normalized_source_entropy": 0.95,
            "mean_packets_per_source": 3.1,
            "udp_packet_ratio": 1.0,
            "window_duration": 1.0,
        }
        # Sub-threshold under defaults (min_aggregate_udp_packets=40, min_unique_sources=10)
        res_default = detect_distributed_udp_flood(features)
        self.assertFalse(res_default.detected)

        # Lowered custom thresholds
        custom_cfg = {
            "min_aggregate_udp_packets": 20,
            "min_aggregate_udp_rate": 20.0,
            "min_aggregate_udp_bytes_per_second": 15_000.0,
            "min_unique_sources": 6,
            "min_source_entropy_bits": 2.5,
        }
        res_custom = detect_distributed_udp_flood(features, thresholds=custom_cfg)
        self.assertTrue(res_custom.detected)
        self.assertEqual(res_custom.attack_type, "DISTRIBUTED_UDP_FLOOD")

    def test_detector_engine_network_level_integration(self):
        """Verify DetectorEngine executes detect_distributed_udp_flood in analyze_network and analyze_context."""
        engine = DetectorEngine(use_ml=False)

        # Verify detect_distributed_udp_flood is in network_detectors
        self.assertTrue(len(engine.network_detectors) >= 1)

        # Distributed UDP attack network features
        network_features = {
            "packets": 400,
            "udp_packets": 400,
            "bytes": 200_000,
            "udp_bytes": 200_000,
            "udp_rate": 400.0,
            "udp_bytes_per_second": 200_000.0,
            "unique_sources": 60,
            "source_ip_entropy": 5.8,
            "normalized_source_entropy": 0.98,
            "mean_packets_per_source": 6.67,
            "udp_packet_ratio": 1.0,
            "window_duration": 1.0,
        }

        # Build context
        context = FeatureContext(
            network=network_features,
            security={"normalized_source_entropy": 0.98},
            sources={f"10.0.0.{i}": {"udp_packets": 6, "packets": 6} for i in range(1, 61)},
        )

        detections = engine.analyze_context(context)

        # Network-level detection must be present under __NETWORK__
        self.assertIn("__NETWORK__", detections)
        net_results = detections["__NETWORK__"]
        self.assertTrue(any(r.attack_type == "DISTRIBUTED_UDP_FLOOD" for r in net_results))

    def test_alert_manager_network_alert_lifecycle(self):
        """Verify AlertManager creates, tracks, and resolves __NETWORK__ alerts."""
        manager = AlertManager(resolve_after=10.0)

        detection = detect_distributed_udp_flood({
            "packets": 350,
            "udp_packets": 350,
            "bytes": 180_000,
            "udp_bytes": 180_000,
            "udp_rate": 350.0,
            "udp_bytes_per_second": 180_000.0,
            "unique_sources": 50,
            "source_ip_entropy": 5.6,
            "normalized_source_entropy": 0.99,
            "mean_packets_per_source": 7.0,
            "udp_packet_ratio": 1.0,
            "window_duration": 1.0,
        })

        t0 = 1000.0
        alerts = manager.process(
            source_ip="__NETWORK__",
            detections=[detection],
            timestamp=t0,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "DISTRIBUTED_UDP_FLOOD")
        self.assertEqual(alerts[0].source_ip, "__NETWORK__")
        self.assertEqual(alerts[0].status, "ACTIVE")

        # Stale resolution after 15 seconds
        resolved = manager.resolve_stale(timestamp=t0 + 15.0)
        resolved_net = [a for a in resolved if a.source_ip == "__NETWORK__" and a.attack_type == "DISTRIBUTED_UDP_FLOOD"]
        self.assertEqual(len(resolved_net), 1)
        self.assertEqual(resolved_net[0].status, "RESOLVED")

    def test_existing_detectors_non_regression(self):
        """Verify per-source UDP flood and SYN flood detectors are not affected."""
        syn_attack = {
            "syn_packet_ratio": 0.95,
            "syn_rate": 150.0,
            "flows_per_second": 150.0,
        }
        res_syn = detect_syn_flood(syn_attack)
        self.assertTrue(res_syn.detected)
        self.assertEqual(res_syn.attack_type, "SYN_FLOOD")

        udp_single_attack = {
            "udp_packets": 250,
            "packets": 250,
            "udp_rate": 250.0,
            "udp_packet_ratio": 1.0,
            "bytes_per_second": 120_000.0,
            "unique_destination_ports": 1,
            "destination_ports": {53},
            "flows_per_second": 40.0,
        }
        res_udp = detect_udp_flood(udp_single_attack)
        self.assertTrue(res_udp.detected)
        self.assertEqual(res_udp.attack_type, "UDP_FLOOD")


if __name__ == "__main__":
    unittest.main()
