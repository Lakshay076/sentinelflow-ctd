"""Regression tests for remaining detector attribution, reflection, and stale-window fixes."""

import os
import tempfile
import unittest

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP

import alerts.alert_store as alert_store_mod
from collector.packet_collector import PacketPipeline
from detectors.udp_flood_detector import WELL_KNOWN_REFLECTION_PORTS
from inference.ml_detector import detect_ml_anomaly


class TestDetectorAuditRegressions(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._old_db_file = alert_store_mod.DB_FILE
        alert_store_mod.DB_FILE = os.path.join(self._tmpdir.name, "audit_alerts.db")

    def tearDown(self):
        alert_store_mod.DB_FILE = self._old_db_file
        self._tmpdir.cleanup()

    def test_1_single_source_udp_flood_with_benign_tcp_not_distributed(self):
        """A single-source UDP flood alongside benign TCP sources must NOT trigger DISTRIBUTED_UDP_FLOOD."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 1000.0

        # 30 unrelated benign TCP sources (1 small ACK each -> raises all-protocol source_ip_entropy > 3.0)
        for i in range(30):
            pkt = IP(src=f"10.10.20.{10 + i}", dst="10.10.10.20") / TCP(
                sport=40000 + i, dport=443, flags="A"
            )
            pkt.time = t0 + 0.05 + i * 0.005
            pipeline.process_packet(pkt)

        # Single attacker 10.10.10.10 sends 40 UDP packets (48 KB/s)
        for i in range(40):
            pkt = (
                IP(src="10.10.10.10", dst="10.10.10.20")
                / UDP(sport=50000 + i, dport=9999)
                / Raw(load=b"U" * 1200)
            )
            pkt.time = t0 + 0.25 + i * 0.01
            pipeline.process_packet(pkt)

        self.assertTrue(pipeline.flush_if_ready(t0 + 1.2))
        active = pipeline.alert_manager.active_alerts()
        attack_types = {(a.source_ip, a.attack_type) for a in active}

        self.assertIn(("10.10.10.10", "UDP_FLOOD"), attack_types)
        self.assertNotIn(("__NETWORK__", "DISTRIBUTED_UDP_FLOOD"), attack_types)

    def test_2_udp_reflection_port_detection_works_end_to_end_and_dhcp_idle_clean(self):
        """Reflection ports must reach detect_udp_flood through SourceAggregator; DHCP follow-up stays clean."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 2000.0

        # Spread 60 high-rate UDP packets across 3 known reflection ports (53, 123, 1900)
        # so unique_destination_ports=3 > MAX_PORTS_FOR_CONCENTRATION(2): only reflection_ports_hit triggers Criterion 4.
        reflection_ports = [53, 123, 1900]
        for i in range(60):
            dp = reflection_ports[i % len(reflection_ports)]
            self.assertIn(dp, WELL_KNOWN_REFLECTION_PORTS)
            pkt = (
                IP(src="10.10.10.10", dst="10.10.10.20")
                / UDP(sport=51000 + i, dport=dp)
                / Raw(load=b"R" * 100)
            )
            pkt.time = t0 + 0.05 + i * 0.01
            pipeline.process_packet(pkt)

        self.assertTrue(pipeline.flush_if_ready(t0 + 1.2))
        active = pipeline.alert_manager.active_alerts()
        udp_alerts = [a for a in active if a.source_ip == "10.10.10.10" and a.attack_type == "UDP_FLOOD"]
        self.assertEqual(len(udp_alerts), 1)
        self.assertTrue(
            any("reflection" in r.lower() for r in udp_alerts[0].reasons),
            f"Expected reflection port reason from live pipeline, got: {udp_alerts[0].reasons}",
        )

        # Resolve W1 alert and emit only a DHCP broadcast in W2
        for a in active:
            pipeline.alert_manager.store.resolve(a.alert_id, timestamp=t0 + 1.3)

        dhcp = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
        dhcp.time = t0 + 1.5
        pipeline.process_packet(dhcp)
        self.assertTrue(pipeline.flush_if_ready(t0 + 2.7))
        self.assertEqual(pipeline.alert_manager.active_alerts(), [])

    def test_3_missed_syn_first_seen_synack_does_not_attribute_beacon_to_responder(self):
        """A missed-SYN first-seen responder SYN+ACK must never flag responder 10.10.10.20 for C2_BEACONING."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 3000.0

        # 6 periodic connections at exact 5.0s intervals where sensor only sees server SYN+ACK (10.10.10.20:443 -> 10.10.10.10:sport)
        for i in range(6):
            ts = t0 + 0.1 + i * 5.0
            rep = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(
                sport=443, dport=52000 + i, flags="SA"
            )
            rep.time = ts
            pipeline.process_packet(rep)
            pipeline.flush_if_ready(ts + 1.1)

        victim_beacons = [
            a
            for a in pipeline.alert_manager.active_alerts()
            if a.source_ip == "10.10.10.20" and a.attack_type == "C2_BEACONING"
        ]
        self.assertEqual(victim_beacons, [], "Responder SYN+ACK must never be flagged as C2_BEACONING")

    def test_4_dns_responses_do_not_attribute_dga_to_dns_server(self):
        """Oversized DNS responses (qr=1) must not attribute DGA_DNS_TUNNELLING to the DNS server 10.10.10.20."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 4000.0

        # Client 10.10.10.10 sends benign low-entropy queries; DNS server 10.10.10.20 sends large responses (qr=1)
        for i in range(8):
            q = (
                IP(src="10.10.10.10", dst="10.10.10.20")
                / UDP(sport=53000 + i, dport=53)
                / DNS(rd=1, qd=DNSQR(qname="api.github.com"))
            )
            q.time = t0 + 0.05 + i * 0.05
            pipeline.process_packet(q)

            r = (
                IP(src="10.10.10.20", dst="10.10.10.10")
                / UDP(sport=53, dport=53000 + i)
                / DNS(qr=1, qd=DNSQR(qname=f"x7k2m9q{i}v8z1p6r3a9b4.tunnel.example"))
                / Raw(load=b"Z" * 600)
            )
            r.time = q.time + 0.01
            pipeline.process_packet(r)

        self.assertTrue(pipeline.flush_if_ready(t0 + 1.2))
        server_dga = [
            a
            for a in pipeline.alert_manager.active_alerts()
            if a.source_ip == "10.10.10.20" and a.attack_type == "DGA_DNS_TUNNELLING"
        ]
        self.assertEqual(server_dga, [], "DNS server responding qr=1 must never trigger DGA_DNS_TUNNELLING")

    def test_5_uniform_tls_server_responses_do_not_trigger_client_splt_anomaly(self):
        """Uniform periodic HTTPS server responses from src_port=443 must not trigger TLS_METADATA_ANOMALY on server."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 5000.0

        # Server 10.10.10.20:443 sends 10 uniform 600B encrypted chunks at steady 100ms intervals to client 10.10.10.10
        for i in range(10):
            srv = (
                IP(src="10.10.10.20", dst="10.10.10.10")
                / TCP(sport=443, dport=54000, flags="PA")
                / Raw(load=b"\x17\x03\x03" + b"E" * 550)
            )
            srv.time = t0 + 0.05 + i * 0.08
            pipeline.process_packet(srv)

        self.assertTrue(pipeline.flush_if_ready(t0 + 1.2))
        server_tls = [
            a
            for a in pipeline.alert_manager.active_alerts()
            if a.source_ip == "10.10.10.20" and a.attack_type == "TLS_METADATA_ANOMALY"
        ]
        self.assertEqual(
            server_tls,
            [],
            f"Server responses from src_port=443 triggered false TLS_METADATA_ANOMALY: {[a.to_dict() for a in server_tls]}",
        )

    def test_6_server_ephemeral_port_replies_do_not_cause_ml_port_fanout_fp(self):
        """Responder replies to 20 ephemeral client ports must not expose ephemeral dst_ports to ML_ANOMALY."""
        pipeline = PacketPipeline(use_ml=True, record_metrics=False)
        t0 = 6000.0

        # Normal 20 connections from client 10.10.10.10 -> server 10.10.10.20:443 with balanced replies
        for i in range(20):
            syn = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=46000 + i, dport=443, flags="S")
            syn.time = t0 + 0.05 + i * 0.03
            pipeline.process_packet(syn)

            sa = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(sport=443, dport=46000 + i, flags="SA")
            sa.time = syn.time + 0.002
            pipeline.process_packet(sa)

            ack = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=46000 + i, dport=443, flags="A") / Raw(load=b"R" * 120)
            ack.time = syn.time + 0.004
            pipeline.process_packet(ack)

            resp = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(sport=443, dport=46000 + i, flags="PA") / Raw(load=b"D" * 120)
            resp.time = syn.time + 0.006
            pipeline.process_packet(resp)

        # Capture SourceAggregator features for 10.10.10.20 before flush resets aggregator
        server_feat = pipeline.source_aggregator.get_features(1.0)["10.10.10.20"]
        self.assertEqual(
            server_feat["observed_unique_destination_ports"],
            0,
            f"Responder ephemeral client ports leaked into observed_unique_destination_ports: {server_feat}",
        )
        self.assertEqual(server_feat["observed_unique_destinations"], 1)

        self.assertTrue(pipeline.flush_if_ready(t0 + 1.2))
        server_ml = [
            a
            for a in pipeline.alert_manager.active_alerts()
            if a.source_ip == "10.10.10.20" and a.attack_type == "ML_ANOMALY"
        ]
        self.assertEqual(
            server_ml,
            [],
            f"Server replies produced false ML_ANOMALY: {[a.to_dict() for a in server_ml]}",
        )

    def test_7_data_exfiltration_attributed_to_sender_and_dhcp_stays_clean(self):
        """Outbound DATA_EXFILTRATION (>500KB) flags only sender 10.10.10.10, and follow-up DHCP stays clean."""
        pipeline = PacketPipeline(use_ml=False, record_metrics=False)
        t0 = 7000.0

        # 400 x 1400B = 560,000B outbound from 10.10.10.10 -> 10.10.10.20 over TCP with minimal ACKs
        syn = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=55000, dport=9000, flags="S")
        syn.time = t0 + 0.01
        pipeline.process_packet(syn)
        sa = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(sport=9000, dport=55000, flags="SA")
        sa.time = t0 + 0.02
        pipeline.process_packet(sa)

        for i in range(400):
            data = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=55000, dport=9000, flags="PA") / Raw(load=b"X" * 1360)
            data.time = t0 + 0.05 + i * 0.002
            pipeline.process_packet(data)

        self.assertTrue(pipeline.flush_if_ready(t0 + 1.2))
        active = pipeline.alert_manager.active_alerts()
        self.assertEqual([(a.source_ip, a.attack_type) for a in active], [("10.10.10.10", "DATA_EXFILTRATION")])

        # Resolve and verify subsequent DHCP broadcast produces zero stale alerts
        for a in active:
            pipeline.alert_manager.store.resolve(a.alert_id, timestamp=t0 + 1.3)

        dhcp = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
        dhcp.time = t0 + 1.5
        pipeline.process_packet(dhcp)
        self.assertTrue(pipeline.flush_if_ready(t0 + 2.7))
        self.assertEqual(pipeline.alert_manager.active_alerts(), [])


if __name__ == "__main__":
    unittest.main()
