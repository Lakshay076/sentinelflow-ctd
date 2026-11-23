"""
Unit and Integration Tests for UDP Volumetric Flood & Reflection Detector

Covers:
1. Normal low-volume UDP traffic (benign / zero false positive).
2. High-volume UDP flood (detected, classification, confidence, severity HIGH).
3. Port concentration and well-known reflection service targeting (e.g., DNS port 53, NTP 123).
4. Sub-threshold UDP traffic (below rate/ratio/packets -> not detected).
5. Missing, empty, or partial feature data (graceful degradation, zero crash).
6. Custom threshold overriding.
7. Passive monitoring constraint (unidirectional vs bidirectional amplification inference).
8. Integration with DetectorEngine (source-level analysis).
9. Integration with AlertManager (alert lifecycle, active store, resolution).
"""

import unittest
from detectors.udp_flood_detector import (
    detect_udp_flood,
    MIN_UDP_RATE,
    MIN_UDP_RATIO,
    MIN_UDP_BYTES_PER_SECOND,
    MIN_UDP_PACKETS,
)
from detectors.detector_engine import DetectorEngine
from features.feature_context import FeatureContext
from alerts.alert_manager import AlertManager


class TestUDPFloodDetector(unittest.TestCase):

    def test_normal_low_volume_udp(self):
        """Benign background UDP (e.g. occasional DNS lookup or NTP sync) must not trigger."""
        features = {
            "udp_packets": 3,
            "packets": 40,
            "bytes": 600,
            "bytes_per_second": 600.0,
            "udp_rate": 3.0,
            "udp_packet_ratio": 0.075,
            "unique_destination_ports": 1,
            "destination_ports": {53},
            "window_duration": 1.0,
        }
        result = detect_udp_flood(features)
        self.assertFalse(result.detected, "Low-volume normal UDP should not be flagged")
        self.assertEqual(result.severity, "NONE")
        self.assertEqual(result.attack_type, None)
        self.assertLess(result.confidence, 0.50)

    def test_high_volume_udp_flood(self):
        """Sustained high-volume UDP flood must trigger with HIGH severity and high confidence."""
        features = {
            "udp_packets": 500,
            "packets": 500,
            "bytes": 250_000,
            "bytes_per_second": 250_000.0,
            "udp_rate": 500.0,
            "udp_packet_ratio": 1.0,
            "unique_destination_ports": 1,
            "destination_ports": {53},
            "flows_per_second": 100.0,
            "window_duration": 1.0,
        }
        result = detect_udp_flood(features)
        self.assertTrue(result.detected, "High-volume UDP flood must be detected")
        self.assertEqual(result.attack_type, "UDP_FLOOD")
        self.assertEqual(result.severity, "HIGH")
        self.assertGreaterEqual(result.confidence, 0.80)
        self.assertGreaterEqual(result.score, 3)

    def test_reflection_port_targeting(self):
        """UDP volumetric flood targeting known reflection service ports (NTP 123) must be flagged."""
        features = {
            "udp_packets": 200,
            "packets": 210,
            "bytes": 120_000,
            "bytes_per_second": 120_000.0,
            "udp_rate": 200.0,
            "udp_packet_ratio": 200 / 210,
            "unique_destination_ports": 1,
            "destination_ports": {123},
            "flows_per_second": 50.0,
            "window_duration": 1.0,
        }
        result = detect_udp_flood(features)
        self.assertTrue(result.detected)
        self.assertEqual(result.attack_type, "UDP_FLOOD")
        reasons_text = " ".join(result.reasons)
        self.assertIn("123", reasons_text)
        self.assertIn("reflection", reasons_text.lower())

    def test_sub_threshold_traffic(self):
        """Traffic below configured rate or packet threshold must not trigger."""
        features = {
            "udp_packets": 12,  # below MIN_UDP_PACKETS (20)
            "packets": 12,
            "bytes": 10_000,
            "bytes_per_second": 10_000.0,
            "udp_rate": 12.0,  # below MIN_UDP_RATE (50.0)
            "udp_packet_ratio": 1.0,
            "unique_destination_ports": 1,
            "window_duration": 1.0,
        }
        result = detect_udp_flood(features)
        self.assertFalse(result.detected, "Sub-threshold traffic must not trigger")
        self.assertEqual(result.severity, "NONE")

    def test_missing_or_empty_features(self):
        """Empty or partial feature dictionaries must degrade gracefully without exceptions."""
        result_empty = detect_udp_flood({})
        self.assertFalse(result_empty.detected)
        self.assertEqual(result_empty.severity, "NONE")
        self.assertEqual(result_empty.score, 0)
        self.assertEqual(result_empty.confidence, 0.0)

        result_partial = detect_udp_flood({"udp_packets": 0, "packets": 100})
        self.assertFalse(result_partial.detected)

    def test_custom_thresholds_override(self):
        """Operators can pass customized thresholds to tune sensitivity."""
        features = {
            "udp_packets": 15,
            "packets": 15,
            "bytes": 10_000,
            "bytes_per_second": 10_000.0,
            "udp_rate": 15.0,
            "udp_packet_ratio": 1.0,
            "unique_destination_ports": 1,
            "window_duration": 1.0,
        }
        # With default threshold (MIN_UDP_PACKETS=20, MIN_UDP_RATE=50.0), this is sub-threshold
        res_default = detect_udp_flood(features)
        self.assertFalse(res_default.detected)

        # With lowered custom thresholds
        custom_cfg = {
            "min_udp_packets": 10,
            "min_udp_rate": 10.0,
            "min_udp_bytes_per_second": 5_000.0,
        }
        res_custom = detect_udp_flood(features, thresholds=custom_cfg)
        self.assertTrue(res_custom.detected)
        self.assertEqual(res_custom.attack_type, "UDP_FLOOD")

    def test_passive_monitoring_constraint(self):
        """
        Passive constraint compliance:
        - When only unidirectional traffic is observed, do not assert verified amplification.
        - When bidirectional legs are both observed with extreme ratio, infer amplification pattern.
        """
        # Unidirectional case (typical passive single-leg tap): bytes_received == 0
        unidirectional = {
            "udp_packets": 300,
            "packets": 300,
            "bytes": 180_000,
            "bytes_received": 0,
            "bytes_per_second": 180_000.0,
            "udp_rate": 300.0,
            "udp_packet_ratio": 1.0,
            "unique_destination_ports": 1,
            "destination_ports": {53},
            "window_duration": 1.0,
        }
        res_uni = detect_udp_flood(unidirectional)
        self.assertTrue(res_uni.detected)
        reasons_uni = " ".join(res_uni.reasons)
        self.assertIn("unidirectional", reasons_uni.lower())
        self.assertIn("unverified", reasons_uni.lower())

        # Bidirectional case: request + response legs visible in mirrored traffic
        bidirectional = {
            "udp_packets": 300,
            "packets": 300,
            "bytes": 200_000,
            "bytes_received": 2000,
            "outbound_inbound_ratio": 100.0,
            "bytes_per_second": 200_000.0,
            "udp_rate": 300.0,
            "udp_packet_ratio": 1.0,
            "unique_destination_ports": 1,
            "destination_ports": {11211},  # Memcached
            "window_duration": 1.0,
        }
        res_bi = detect_udp_flood(bidirectional)
        self.assertTrue(res_bi.detected)
        reasons_bi = " ".join(res_bi.reasons)
        self.assertIn("asymmetric byte ratio", reasons_bi.lower())
        self.assertIn("suggestive of amplification", reasons_bi.lower())

    def test_detector_engine_integration(self):
        """Verify DetectorEngine integrates UDP flood detector in source analysis."""
        engine = DetectorEngine(use_ml=False)

        udp_attacker_features = {
            "udp_packets": 400,
            "packets": 400,
            "bytes": 220_000,
            "bytes_per_second": 220_000.0,
            "udp_rate": 400.0,
            "udp_packet_ratio": 1.0,
            "unique_destination_ports": 1,
            "destination_ports": {53},
            "flows_per_second": 80.0,
            "window_duration": 1.0,
        }
        benign_host_features = {
            "udp_packets": 2,
            "packets": 50,
            "bytes": 4000,
            "bytes_per_second": 4000.0,
            "udp_rate": 2.0,
            "udp_packet_ratio": 0.04,
            "unique_destination_ports": 1,
            "window_duration": 1.0,
        }

        context = FeatureContext(
            network={"packets": 450, "bytes": 224_000},
            sources={
                "10.0.0.99": udp_attacker_features,
                "10.0.0.10": benign_host_features,
            },
        )

        detections = engine.analyze_context(context)

        self.assertIn("10.0.0.99", detections)
        self.assertIn("10.0.0.10", detections)

        attacker_results = detections["10.0.0.99"]
        self.assertTrue(any(r.attack_type == "UDP_FLOOD" for r in attacker_results))

        benign_results = detections["10.0.0.10"]
        self.assertEqual(len(benign_results), 0, "Benign host must produce zero detections")

    def test_alert_manager_lifecycle(self):
        """Verify AlertManager processes, stores, updates, and resolves UDP_FLOOD alerts."""
        manager = AlertManager(resolve_after=10.0)

        detection = detect_udp_flood({
            "udp_packets": 350,
            "packets": 350,
            "bytes": 180_000,
            "bytes_per_second": 180_000.0,
            "udp_rate": 350.0,
            "udp_packet_ratio": 1.0,
            "unique_destination_ports": 1,
            "destination_ports": {53},
            "window_duration": 1.0,
        })

        t0 = 1000.0
        alerts = manager.process(
            source_ip="10.0.0.99",
            detections=[detection],
            timestamp=t0,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "UDP_FLOOD")
        self.assertEqual(alerts[0].source_ip, "10.0.0.99")
        self.assertEqual(alerts[0].status, "ACTIVE")

        active_for_source = [
            a for a in manager.active_alerts()
            if a.source_ip == "10.0.0.99" and a.attack_type == "UDP_FLOOD"
        ]
        self.assertEqual(len(active_for_source), 1)

        # Stale resolution after timeout
        resolved = manager.resolve_stale(timestamp=t0 + 15.0)
        resolved_for_source = [
            a for a in resolved
            if a.source_ip == "10.0.0.99" and a.attack_type == "UDP_FLOOD"
        ]
        self.assertEqual(len(resolved_for_source), 1)
        self.assertEqual(resolved_for_source[0].status, "RESOLVED")


if __name__ == "__main__":
    unittest.main()
