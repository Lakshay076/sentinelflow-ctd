"""
Unit & Integration Tests for Port Scan Detector (Vertical & Horizontal Sweeps)

Covers:
1. Vertical scan — many ports on single/few targets (still detected).
2. Horizontal scan — single/few ports across many destination hosts (detected).
3. Normal browsing across many hosts (e.g. CDNs/web browsing with established traffic) — not flagged.
4. Many hosts but low connection-attempt evidence — not flagged.
5. Traffic below threshold — not flagged.
6. Window expiration and aggregation behavior — resets between windows.
7. Missing or incomplete feature data — graceful degradation, zero exceptions.
8. Custom threshold overriding.
9. Regression verification with existing victim-response profile.
"""

import unittest
from detectors.scan_detector import (
    detect_port_scan,
    MIN_DESTINATION_PORTS,
    MIN_DESTINATION_HOSTS,
    MIN_SYN_RATIO,
    MIN_HORIZONTAL_SYN_RATIO,
)
from features.source_aggregation import SourceAggregator
from features.behavior_window import BehaviorWindow
from detectors.detector_engine import DetectorEngine
from features.feature_context import FeatureContext


class TestPortScanDetector(unittest.TestCase):

    def test_vertical_scan_detected(self):
        """Vertical scan (probing 10 ports on a target with high SYN ratio) must be detected."""
        vertical_attack = {
            "unique_destination_ports": 10,
            "unique_destinations": 1,
            "active_flows": 11,
            "syn_packet_ratio": 0.85,
            "flows_per_second": 11.0,
            "ports_per_destination": 10.0,
        }
        result = detect_port_scan(vertical_attack)
        self.assertTrue(result.detected, "Vertical port scan must be detected")
        self.assertEqual(result.attack_type, "PORT_SCAN")
        self.assertIn(result.severity, ["MEDIUM", "HIGH"])
        self.assertGreaterEqual(result.confidence, 0.75)
        reasons_text = " ".join(result.reasons)
        self.assertIn("vertical", reasons_text.lower())
        self.assertIn("port diversity", reasons_text.lower())

    def test_horizontal_scan_detected(self):
        """Horizontal host sweep (probing port 22 across 25 destination hosts) must be detected."""
        horizontal_attack = {
            "unique_destination_ports": 1,
            "unique_destinations": 25,
            "active_flows": 25,
            "syn_packet_ratio": 0.95,
            "flows_per_second": 25.0,
            "ports_per_destination": 1 / 25,
        }
        result = detect_port_scan(horizontal_attack)
        self.assertTrue(result.detected, "Horizontal host sweep must be detected")
        self.assertEqual(result.attack_type, "PORT_SCAN")
        self.assertEqual(result.severity, "HIGH")
        self.assertGreaterEqual(result.confidence, 0.75)
        reasons_text = " ".join(result.reasons)
        self.assertIn("horizontal", reasons_text.lower())
        self.assertIn("fan-out", reasons_text.lower())

    def test_normal_browsing_many_hosts_not_flagged(self):
        """Normal web browsing across 15 external CDN/web hosts (low SYN ratio, mostly data/ACKs) must NOT be flagged."""
        normal_browsing = {
            "unique_destination_ports": 2,  # ports 80 and 443
            "unique_destinations": 15,
            "active_flows": 15,
            "syn_packet_ratio": 0.08,  # Only initial handshake SYNs, 92% data/ACKs
            "flows_per_second": 5.0,
            "ports_per_destination": 2 / 15,
        }
        result = detect_port_scan(normal_browsing)
        self.assertFalse(result.detected, "Normal browsing across hosts must not be flagged")
        self.assertEqual(result.severity, "NONE")
        self.assertIsNone(result.attack_type)

    def test_many_hosts_low_connection_evidence_not_flagged(self):
        """Source contacting many hosts but with low connection attempts and low SYN ratio must NOT be flagged."""
        low_evidence = {
            "unique_destination_ports": 1,
            "unique_destinations": 20,
            "active_flows": 3,  # Below MIN_HORIZONTAL_FLOWS (8)
            "syn_packet_ratio": 0.20,  # Below MIN_HORIZONTAL_SYN_RATIO (0.50)
            "flows_per_second": 1.0,  # Below MIN_HORIZONTAL_FLOW_RATE (5.0)
            "ports_per_destination": 1 / 20,
        }
        result = detect_port_scan(low_evidence)
        self.assertFalse(result.detected, "Low connection-attempt evidence must not trigger")
        self.assertEqual(result.severity, "NONE")

    def test_traffic_below_threshold_not_flagged(self):
        """Traffic below destination and port thresholds must NOT be flagged."""
        below_threshold = {
            "unique_destination_ports": 2,  # Below vertical threshold 5
            "unique_destinations": 4,       # Below horizontal threshold 8
            "active_flows": 4,
            "syn_packet_ratio": 0.80,
            "flows_per_second": 4.0,
            "ports_per_destination": 0.5,
        }
        result = detect_port_scan(below_threshold)
        self.assertFalse(result.detected, "Sub-threshold traffic must not be flagged")
        self.assertEqual(result.severity, "NONE")

    def test_missing_or_empty_feature_data(self):
        """Empty or partial feature dictionaries must degrade safely with zero exception."""
        result_empty = detect_port_scan({})
        self.assertFalse(result_empty.detected)
        self.assertEqual(result_empty.severity, "NONE")
        self.assertEqual(result_empty.score, 0)
        self.assertEqual(result_empty.confidence, 0.0)

        result_partial = detect_port_scan({"unique_destinations": 50})
        self.assertFalse(result_partial.detected)

    def test_custom_thresholds_override(self):
        """Operators can pass customized thresholds to tune scan sensitivity."""
        features = {
            "unique_destination_ports": 1,
            "unique_destinations": 5,  # Below default horizontal threshold (8)
            "active_flows": 5,
            "syn_packet_ratio": 0.90,
            "flows_per_second": 5.0,
            "ports_per_destination": 0.2,
        }
        # Sub-threshold under defaults
        res_default = detect_port_scan(features)
        self.assertFalse(res_default.detected)

        # Lowered custom thresholds
        custom_cfg = {
            "min_destination_hosts": 5,
            "min_horizontal_flows": 5,
            "min_horizontal_syn_ratio": 0.50,
            "min_flows": 5,
        }
        res_custom = detect_port_scan(features, thresholds=custom_cfg)
        self.assertTrue(res_custom.detected)
        self.assertEqual(res_custom.attack_type, "PORT_SCAN")

    def test_victim_response_profile_non_regression(self):
        """Victim responding to multi-port scan (high ports, but syn_ratio=0.0) must never be flagged."""
        victim_response = {
            "unique_destination_ports": 93,
            "unique_destinations": 1,
            "active_flows": 93,
            "syn_packet_ratio": 0.0,
            "flows_per_second": 93.0,
            "ports_per_destination": 93.0,
        }
        result = detect_port_scan(victim_response)
        self.assertFalse(result.detected, "Victim response traffic must not be flagged as a scan")
        self.assertEqual(result.severity, "NONE")

    def test_window_expiration_and_aggregation(self):
        """Verify SourceAggregator accumulates horizontal destination IPs and resets cleanly across windows."""
        aggregator = SourceAggregator()

        # Window 1: Attacker 10.0.0.99 sweeps 12 different hosts on port 22
        for i in range(12):
            aggregator.add_packet(
                src_ip="10.0.0.99",
                dst_ip=f"192.168.1.{i+1}",
                protocol="TCP",
                packet_bytes=60,
                src_port=40000 + i,
                dst_port=22,
                tcp_syn=True,
            )

        features_win1 = aggregator.get_features(duration=1.0)
        self.assertIn("10.0.0.99", features_win1)
        src_features = features_win1["10.0.0.99"]
        self.assertEqual(src_features["unique_destinations"], 12)
        self.assertEqual(src_features["unique_destination_ports"], 1)
        self.assertEqual(src_features["syn_packet_ratio"], 1.0)

        # Evaluate detection on Window 1 features
        result_win1 = detect_port_scan(src_features)
        self.assertTrue(result_win1.detected)
        self.assertEqual(result_win1.attack_type, "PORT_SCAN")

        # Window Reset
        aggregator.reset()

        # Window 2: Only 1 benign packet
        aggregator.add_packet(
            src_ip="10.0.0.99",
            dst_ip="192.168.1.1",
            protocol="TCP",
            packet_bytes=60,
            src_port=40000,
            dst_port=80,
            tcp_syn=False,
            tcp_ack=True,
        )
        features_win2 = aggregator.get_features(duration=1.0)
        self.assertEqual(features_win2["10.0.0.99"]["unique_destinations"], 0)  # No SYNs, so 0 connection destinations
        result_win2 = detect_port_scan(features_win2["10.0.0.99"])
        self.assertFalse(result_win2.detected)

    def test_slow_horizontal_scan_detected(self):
        """Slow horizontal scan (probing 10 destination hosts over rolling window at 1 host/sec) must be detected."""
        slow_attack = {
            "unique_destination_ports": 1,
            "unique_destinations": 1,         # Only 1 host in instantaneous 1-second slice
            "active_flows": 1,
            "syn_packet_ratio": 1.0,
            "flows_per_second": 1.0,
            "rolling_unique_destinations": 10,  # 10 hosts contacted across 10s BehaviorWindow
            "rolling_unique_destination_ports": 1,
            "rolling_active_flows": 10,
            "rolling_tcp_syn": 10,
            "rolling_syn_ratio": 1.0,
            "rolling_ports_per_destination": 0.1,
            "rolling_flows_per_second": 1.0,
        }
        result = detect_port_scan(slow_attack)
        self.assertTrue(result.detected, "Slow-and-low horizontal sweep must be detected")
        self.assertEqual(result.attack_type, "PORT_SCAN")
        self.assertIn(result.severity, ["MEDIUM", "HIGH"])
        self.assertGreaterEqual(result.confidence, 0.75)
        reasons_text = " ".join(result.reasons)
        self.assertIn("slow-and-low", reasons_text.lower())
        self.assertIn("rolling window", reasons_text.lower())

    def test_slow_horizontal_scan_high_severity(self):
        """Sustained slow sweep (>=12 hosts and >=10 SYNs) achieves HIGH severity and 1.0 confidence."""
        sustained_slow_attack = {
            "rolling_unique_destinations": 15,
            "rolling_unique_destination_ports": 1,
            "rolling_active_flows": 15,
            "rolling_tcp_syn": 15,
            "rolling_syn_ratio": 1.0,
            "rolling_ports_per_destination": 1 / 15,
            "flows_per_second": 1.5,
        }
        result = detect_port_scan(sustained_slow_attack)
        self.assertTrue(result.detected)
        self.assertEqual(result.severity, "HIGH")
        self.assertEqual(result.confidence, 1.0)

    def test_slow_scan_normal_browsing_rolling_not_flagged(self):
        """Normal web browsing across 15 external hosts over 10 seconds (low SYN ratio, mostly data/ACKs) must NOT be flagged."""
        normal_browsing_rolling = {
            "unique_destination_ports": 2,
            "unique_destinations": 2,
            "active_flows": 2,
            "syn_packet_ratio": 0.05,
            "rolling_unique_destinations": 15,
            "rolling_unique_destination_ports": 2,
            "rolling_active_flows": 15,
            "rolling_tcp_syn": 15,
            "rolling_syn_ratio": 0.08,  # Only initial SYNs out of ~190 packets
            "rolling_ports_per_destination": 2 / 15,
            "rolling_flows_per_second": 1.5,
        }
        result = detect_port_scan(normal_browsing_rolling)
        self.assertFalse(result.detected, "Normal browsing over rolling window must not be flagged")
        self.assertEqual(result.severity, "NONE")
        self.assertIsNone(result.attack_type)

    def test_slow_scan_insufficient_syn_not_flagged(self):
        """Source contacting 10 hosts across rolling window but with insufficient SYN attempts (<6) must NOT be flagged."""
        insufficient_syn = {
            "rolling_unique_destinations": 10,
            "rolling_unique_destination_ports": 1,
            "rolling_active_flows": 10,
            "rolling_tcp_syn": 3,       # Below MIN_SLOW_SCAN_SYN_PACKETS (6)
            "rolling_syn_ratio": 0.30,  # Below MIN_SLOW_SCAN_SYN_RATIO (0.50)
            "rolling_ports_per_destination": 0.1,
        }
        result = detect_port_scan(insufficient_syn)
        self.assertFalse(result.detected, "Insufficient SYN evidence must not trigger slow scan alert")
        self.assertEqual(result.severity, "NONE")

    def test_slow_scan_via_behavior_window_streaming(self):
        """End-to-end integration: BehaviorWindow tracks slow reconnaissance over 10s and DetectorEngine alerts."""
        behavior_win = BehaviorWindow(window_seconds=10.0)
        engine = DetectorEngine()

        # Attacker 10.0.0.99 probes 1 distinct host every second on port 22 (10 hosts over 10 seconds)
        for i in range(10):
            timestamp = float(i + 1)
            behavior_win.add_packet(
                timestamp=timestamp,
                src_ip="10.0.0.99",
                dst_ip=f"192.168.1.{i+1}",
                protocol="TCP",
                packet_bytes=60,
                src_port=40000 + i,
                dst_port=22,
                tcp_syn=True,
                tcp_ack=False,
                tcp_rst=False,
            )

        # Benign client 10.0.0.50 browses 10 hosts with real traffic (1 SYN + 9 ACKs/data per host)
        for i in range(10):
            timestamp = float(i + 1)
            # SYN
            behavior_win.add_packet(
                timestamp=timestamp,
                src_ip="10.0.0.50",
                dst_ip=f"172.16.0.{i+1}",
                protocol="TCP",
                packet_bytes=60,
                src_port=50000 + i,
                dst_port=443,
                tcp_syn=True,
                tcp_ack=False,
                tcp_rst=False,
            )
            # 9 data/ACK packets
            for j in range(9):
                behavior_win.add_packet(
                    timestamp=timestamp + (j + 1) * 0.05,
                    src_ip="10.0.0.50",
                    dst_ip=f"172.16.0.{i+1}",
                    protocol="TCP",
                    packet_bytes=1420,
                    src_port=50000 + i,
                    dst_port=443,
                    tcp_syn=False,
                    tcp_ack=True,
                    tcp_rst=False,
                )

        behavior_features = behavior_win.get_source_features(current_timestamp=10.5)
        self.assertIn("10.0.0.99", behavior_features)
        self.assertIn("10.0.0.50", behavior_features)

        # Check behavior features
        attacker_b = behavior_features["10.0.0.99"]
        self.assertEqual(attacker_b["unique_destinations"], 10)
        self.assertEqual(attacker_b["unique_destination_ports"], 1)
        self.assertEqual(attacker_b["syn_packet_ratio"], 1.0)

        benign_b = behavior_features["10.0.0.50"]
        self.assertEqual(benign_b["unique_destinations"], 10)
        self.assertEqual(benign_b["unique_destination_ports"], 1)
        self.assertLess(benign_b["syn_packet_ratio"], 0.15)  # ~0.10

        # Build FeatureContext with rolling behavior and evaluate
        context = FeatureContext(
            network={},
            security={},
            sources={},  # Empty instantaneous window simulates slow stealthy rate
            behavior=behavior_features,
        )

        detections = engine.analyze_context(context)

        # Attacker 10.0.0.99 must be flagged for PORT_SCAN
        self.assertIn("10.0.0.99", detections)
        attacker_results = detections["10.0.0.99"]
        scan_alerts = [r for r in attacker_results if r.attack_type == "PORT_SCAN"]
        self.assertTrue(len(scan_alerts) >= 1, "Attacker must trigger PORT_SCAN alert")
        self.assertIn(scan_alerts[0].severity, ["MEDIUM", "HIGH"])
        self.assertTrue(any("slow-and-low" in r.lower() for r in scan_alerts[0].reasons))

        # Benign client 10.0.0.50 must NOT be flagged
        benign_results = detections.get("10.0.0.50", [])
        benign_scan_alerts = [r for r in benign_results if r.attack_type == "PORT_SCAN"]
        self.assertEqual(len(benign_scan_alerts), 0, "Benign client must not trigger PORT_SCAN")

    def test_rolling_window_expiration_slow_scan(self):
        """Verify events outside the 10.0-second BehaviorWindow expire cleanly and memory remains bounded."""
        behavior_win = BehaviorWindow(window_seconds=10.0)

        # Probes added at t = 1.0 .. 10.0
        for i in range(10):
            behavior_win.add_packet(
                timestamp=float(i + 1),
                src_ip="10.0.0.99",
                dst_ip=f"192.168.1.{i+1}",
                protocol="TCP",
                packet_bytes=60,
                src_port=40000 + i,
                dst_port=22,
                tcp_syn=True,
            )

        self.assertEqual(behavior_win.size(), 10)

        # Advance time to t = 21.0s (all previous events are > 10s old)
        expired_features = behavior_win.get_source_features(current_timestamp=21.0)
        self.assertEqual(len(expired_features), 0, "All expired events must be purged")
        self.assertEqual(behavior_win.size(), 0, "Behavior window queue must be empty")

    def test_benign_10_0_0_17_mixed_window_not_flagged(self):
        """
        Regression test for 10.0.0.17 in test_api.pcap:
        A 1s slice with 1 SYN packet (syn_packet_ratio=1.0) combined with a 10s
        rolling BehaviorWindow holding 9 destinations / 13 flows (mostly ACKs/DNS,
        rolling_syn_ratio ~ 0.14) must NOT fabricate a horizontal PORT_SCAN.
        """
        aggregator = SourceAggregator()
        behavior_win = BehaviorWindow(window_seconds=10.0)
        engine = DetectorEngine(use_ml=False)

        # Prior 9 seconds of benign ACK and DNS traffic from 10.0.0.17 (8 distinct hosts, 3 ports)
        benign_events = [
            (2.0, "203.0.113.11", "TCP", 443, False, True),
            (3.0, "203.0.113.26", "TCP", 80, False, True),
            (4.0, "8.8.8.8", "UDP", 53, False, False),
            (5.0, "203.0.113.15", "TCP", 443, False, True),
            (6.0, "203.0.113.20", "TCP", 80, True, False),
            (6.2, "203.0.113.10", "TCP", 80, False, True),
            (6.6, "203.0.113.18", "TCP", 443, False, True),
            (6.7, "203.0.113.18", "TCP", 80, False, True),
            (7.7, "203.0.113.9", "TCP", 80, False, True),
            (9.4, "203.0.113.20", "TCP", 443, False, True),
            (10.3, "203.0.113.8", "TCP", 80, False, True),
        ]
        for idx, (ts, dst, proto, dport, syn, ack) in enumerate(benign_events):
            behavior_win.add_packet(
                timestamp=ts,
                src_ip="10.0.0.17",
                dst_ip=dst,
                protocol=proto,
                packet_bytes=200,
                src_port=40000 + idx,
                dst_port=dport,
                tcp_syn=syn,
                tcp_ack=ack,
            )

        # Latest 1-second window has ONLY 1 SYN packet -> 1s syn_packet_ratio == 1.0
        pkt_ts = 10.9
        behavior_win.add_packet(
            timestamp=pkt_ts,
            src_ip="10.0.0.17",
            dst_ip="203.0.113.10",
            protocol="TCP",
            packet_bytes=247,
            src_port=48704,
            dst_port=80,
            tcp_syn=True,
            tcp_ack=False,
        )
        aggregator.add_packet(
            src_ip="10.0.0.17",
            dst_ip="203.0.113.10",
            protocol="TCP",
            packet_bytes=247,
            src_port=48704,
            dst_port=80,
            tcp_syn=True,
            tcp_ack=False,
            initiator_ip="10.0.0.17",
            responder_ip="203.0.113.10",
        )

        source_features = aggregator.get_features(duration=1.0)
        behavior_features = behavior_win.get_source_features(current_timestamp=11.0)
        context = FeatureContext(
            network={},
            security={},
            sources=source_features,
            behavior=behavior_features,
        )

        combined = context.get_combined_source_features("10.0.0.17")
        # Short-window features stay internally consistent (1s)
        self.assertEqual(combined["unique_destinations"], 1)
        self.assertEqual(combined["syn_packet_ratio"], 1.0)
        # Rolling features stay internally consistent (10s)
        self.assertGreaterEqual(combined["rolling_unique_destinations"], 8)
        self.assertLess(combined["rolling_syn_ratio"], 0.25)

        detections = engine.analyze_context(context)
        scan_alerts = [
            r for r in detections.get("10.0.0.17", []) if r.attack_type == "PORT_SCAN"
        ]
        self.assertEqual(len(scan_alerts), 0, "Mixed 1s/10s windows must not fabricate PORT_SCAN")


def main():
    print("=" * 70)
    print("CTD — PORT SCAN DETECTOR (VERTICAL & HORIZONTAL) TEST")
    print("=" * 70)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestPortScanDetector)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)


if __name__ == "__main__":
    main()
