"""Regression tests for source/responder attribution and historical window scoping."""

import os
import tempfile
import unittest

from scapy.all import IP, TCP, UDP

import alerts.alert_store as alert_store_mod
from collector.packet_collector import PacketPipeline
from detectors.detector_engine import DetectorEngine
from features.behavior_window import BehaviorWindow
from features.feature_context import FeatureContext
from features.source_aggregation import SourceAggregator


def _make_syn_flood_and_replies(pipeline: PacketPipeline, t0: float, count: int = 120):
    for i in range(count):
        pkt = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=40000 + i, dport=80, flags="S")
        pkt.time = t0 + 0.05 + i * 0.005
        pipeline.process_packet(pkt)

        rep = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(sport=80, dport=40000 + i, flags="SA")
        rep.time = pkt.time + 0.001
        pipeline.process_packet(rep)


class TestAttributionRegression(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._old_db_file = alert_store_mod.DB_FILE
        alert_store_mod.DB_FILE = os.path.join(self._tmpdir.name, "attr_alerts.db")

    def tearDown(self):
        alert_store_mod.DB_FILE = self._old_db_file
        self._tmpdir.cleanup()

    def test_syn_flood_followed_by_idle_window_does_not_refire_or_misattribute(self):
        """An idle window after a SYN flood must not emit SYN_FLOOD or PORT_SCAN for attacker or victim."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 1000.0
        _make_syn_flood_and_replies(pipeline, t0, count=120)

        # Flush Window 1 (t0+0.05 .. t0+1.1)
        flushed = pipeline.flush_if_ready(t0 + 1.2)
        self.assertTrue(flushed)
        alerts_w1 = pipeline.alert_manager.active_alerts()
        self.assertEqual([(a.source_ip, a.attack_type) for a in alerts_w1], [("10.10.10.10", "SYN_FLOOD")])

        # Resolve alerts, then evaluate an empty/idle Window 2 against preserved BehaviorWindow
        for a in alerts_w1:
            pipeline.alert_manager.store.resolve(a.alert_id, timestamp=t0 + 1.3)

        behavior_w2 = pipeline.behavior_window.get_source_features(current_timestamp=t0 + 2.2)
        self.assertIn("10.10.10.10", behavior_w2)
        self.assertIn("10.10.10.20", behavior_w2)
        # Victim must have zero connection/scan metrics even inside BehaviorWindow
        self.assertEqual(behavior_w2["10.10.10.20"]["unique_destination_ports"], 0)
        self.assertEqual(behavior_w2["10.10.10.20"]["active_flows"], 0)
        self.assertEqual(behavior_w2["10.10.10.20"]["tcp_syn"], 0)

        idle_ctx = FeatureContext(
            network={"window_duration": 1.0, "packets": 0, "bytes": 0},
            sources={},
            behavior=behavior_w2,
        )
        detections_w2 = pipeline.detector_engine.analyze_context(idle_ctx)
        self.assertEqual(detections_w2, {})
        self.assertEqual(pipeline.alert_manager.active_alerts(), [])

    def test_syn_flood_followed_by_dhcp_broadcast_no_victim_or_stale_alerts(self):
        """A single 0.0.0.0 DHCP packet after a 500-pkt SYN flood must not emit victim or stale alerts."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 2000.0
        # 500 SYNs + 500 SA replies inside a single 1s window (t0+0.05 .. t0+0.55)
        for i in range(500):
            pkt = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=40000 + i, dport=80, flags="S")
            pkt.time = t0 + 0.05 + i * 0.001
            pipeline.process_packet(pkt)
            rep = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(sport=80, dport=40000 + i, flags="SA")
            rep.time = pkt.time + 0.0005
            pipeline.process_packet(rep)

        # Flush Window 1 at t0+1.2 (simulating 1s window completion)
        self.assertTrue(pipeline.flush_if_ready(t0 + 1.2))
        alerts_after_w1 = pipeline.alert_manager.active_alerts()
        self.assertEqual([(a.source_ip, a.attack_type) for a in alerts_after_w1], [("10.10.10.10", "SYN_FLOOD")])

        # Resolve W1 alert so any stale re-emission in W2 would create a brand-new active alert
        for a in alerts_after_w1:
            pipeline.alert_manager.store.resolve(a.alert_id, timestamp=t0 + 1.3)

        # Window 2 contains ONLY a single DHCP broadcast (0.0.0.0 -> 255.255.255.255)
        dhcp = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
        dhcp.time = t0 + 1.5
        pipeline.process_packet(dhcp)
        self.assertTrue(pipeline.flush_if_ready(t0 + 2.7))

        alerts_after_w2 = pipeline.alert_manager.active_alerts()
        self.assertEqual(
            alerts_after_w2,
            [],
            f"DHCP window emitted unexpected alerts: {[a.to_dict() for a in alerts_after_w2]}",
        )

    def test_port_scan_followed_by_idle_window_no_duplicate_incident(self):
        """A vertical/horizontal port scan followed by an idle/unrelated window must not re-fire."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 3000.0

        for idx, port in enumerate(range(20, 45)):
            pkt = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=45000 + idx, dport=port, flags="S")
            pkt.time = t0 + 0.05 + idx * 0.01
            pipeline.process_packet(pkt)
            rep = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(sport=port, dport=45000 + idx, flags="RA")
            rep.time = pkt.time + 0.001
            pipeline.process_packet(rep)

        self.assertTrue(pipeline.flush_if_ready(t0 + 1.2))
        w1_alerts = pipeline.alert_manager.active_alerts()
        self.assertEqual([(a.source_ip, a.attack_type) for a in w1_alerts], [("10.10.10.10", "PORT_SCAN")])

        for a in w1_alerts:
            pipeline.alert_manager.store.resolve(a.alert_id, timestamp=t0 + 1.3)

        # Subsequent window with unrelated 0.0.0.0 DHCP packet
        dhcp = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
        dhcp.time = t0 + 2.0
        pipeline.process_packet(dhcp)
        pipeline.flush_if_ready(t0 + 3.2)

        self.assertEqual(pipeline.alert_manager.active_alerts(), [])

    def test_responder_ack_rst_and_synack_never_inherit_attacker_scan_metrics(self):
        """Responder SYN+ACK, ACK, and RST replies must yield 0 scan/SYN/flow metrics in both aggregators."""
        sa = SourceAggregator()
        bw = BehaviorWindow(window_seconds=10.0)

        for i in range(50):
            # Attacker 10.10.10.10 SYN
            sa.add_packet(
                src_ip="10.10.10.10", dst_ip="10.10.10.20", protocol="TCP", packet_bytes=60,
                src_port=40000 + i, dst_port=80, tcp_syn=True, tcp_ack=False, tcp_rst=False,
                initiator_ip="10.10.10.10", responder_ip="10.10.10.20",
            )
            bw.add_packet(
                timestamp=10.0 + i * 0.01,
                src_ip="10.10.10.10", dst_ip="10.10.10.20", protocol="TCP", packet_bytes=60,
                src_port=40000 + i, dst_port=80, tcp_syn=True, tcp_ack=False, tcp_rst=False,
                initiator_ip="10.10.10.10", responder_ip="10.10.10.20",
            )
            # Victim 10.10.10.20 SYN+ACK and RST+ACK replies to attacker's 50 source ports
            sa.add_packet(
                src_ip="10.10.10.20", dst_ip="10.10.10.10", protocol="TCP", packet_bytes=60,
                src_port=80, dst_port=40000 + i, tcp_syn=True, tcp_ack=True, tcp_rst=False,
                initiator_ip="10.10.10.10", responder_ip="10.10.10.20",
            )
            bw.add_packet(
                timestamp=10.005 + i * 0.01,
                src_ip="10.10.10.20", dst_ip="10.10.10.10", protocol="TCP", packet_bytes=60,
                src_port=80, dst_port=40000 + i, tcp_syn=True, tcp_ack=True, tcp_rst=False,
                initiator_ip="10.10.10.10", responder_ip="10.10.10.20",
            )
            bw.add_packet(
                timestamp=10.006 + i * 0.01,
                src_ip="10.10.10.20", dst_ip="10.10.10.10", protocol="TCP", packet_bytes=54,
                src_port=80, dst_port=40000 + i, tcp_syn=False, tcp_ack=True, tcp_rst=True,
                initiator_ip="10.10.10.10", responder_ip="10.10.10.20",
            )

        s_feat = sa.get_features(1.0)
        b_feat = bw.get_source_features(11.0)

        for feat_map in (s_feat, b_feat):
            victim = feat_map["10.10.10.20"]
            self.assertEqual(victim["tcp_syn"], 0)
            self.assertEqual(victim["syn_rate"], 0.0)
            self.assertEqual(victim["unique_destinations"], 0)
            self.assertEqual(victim["unique_destination_ports"], 0)
            self.assertEqual(victim["active_flows"], 0)
            self.assertGreater(victim["packets"], 0)

            attacker = feat_map["10.10.10.10"]
            self.assertEqual(attacker["tcp_syn"], 50)
            self.assertEqual(attacker["active_flows"], 50)

    def test_legitimate_rolling_scan_retains_correct_initiator_attribution(self):
        """A genuine slow-and-low horizontal scan across 10s still flags only the true initiator."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 4000.0

        # Slow scan: 10.10.10.10 probes 10 different targets on port 22, 1 every 0.8s, with SA replies
        for i in range(10):
            target = f"10.10.10.{20 + i}"
            ts = t0 + i * 0.8
            pkt = IP(src="10.10.10.10", dst=target) / TCP(sport=50000 + i, dport=22, flags="S")
            pkt.time = ts
            pipeline.process_packet(pkt)

            rep = IP(src=target, dst="10.10.10.10") / TCP(sport=22, dport=50000 + i, flags="SA")
            rep.time = ts + 0.01
            pipeline.process_packet(rep)

        pipeline.flush_if_ready(t0 + 9.0)
        active = pipeline.alert_manager.active_alerts()
        self.assertEqual([(a.source_ip, a.attack_type) for a in active], [("10.10.10.10", "PORT_SCAN")])
        self.assertEqual(active[0].initiator_ip, "10.10.10.10")


if __name__ == "__main__":
    unittest.main()
