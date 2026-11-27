"""Regression tests for same-window, cross-window, and victim-side ML correlation."""

import os
import tempfile
import unittest

from scapy.all import IP, TCP

import alerts.alert_store as alert_store_mod
from alerts.alert_manager import AlertManager
from collector.packet_collector import PacketPipeline
from detectors.detection_result import DetectionResult
from detectors.incident_correlator import IncidentCorrelator


def _syn_flood_det(conf=1.0):
    return DetectionResult(
        detected=True,
        attack_type="SYN_FLOOD",
        severity="HIGH",
        score=3,
        confidence=conf,
        reasons=["high SYN packet ratio (1.00)", "high SYN rate (96.00 SYN/sec)"],
    )


def _port_scan_det(conf=0.75):
    return DetectionResult(
        detected=True,
        attack_type="PORT_SCAN",
        severity="MEDIUM",
        score=3,
        confidence=conf,
        reasons=["high destination-port diversity (25 ports)", "multiple connection attempts (25 flows)"],
    )


def _ml_det(conf=0.35, reasons=None):
    return DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="LOW",
        score=1,
        confidence=conf,
        reasons=reasons
        or [
            "flows_per_second unusually higher than normal (value=44.00, z-score=59.3)",
            "packets_per_second unusually higher than normal (value=44.00, z-score=16.0)",
        ],
    )


def _comm_ctx(attacker, victim):
    flow = {
        "flow_id": f"{attacker}:41000<->{victim}:80/TCP",
        "protocol": "TCP",
        "src_ip": attacker,
        "dst_ip": victim,
        "src_port": 41000,
        "dst_port": 80,
        "initiator_ip": attacker,
        "responder_ip": victim,
    }
    return {
        attacker: {
            "source_ip": attacker,
            "initiator_ip": attacker,
            "responder_ips": [victim],
            "observed_peers": [victim],
            "related_flows": [flow],
        },
        victim: {
            "source_ip": victim,
            "initiator_ip": None,
            "responder_ips": [],
            "observed_peers": [attacker],
            "related_flows": [flow],
        },
    }


class TestIncidentCorrelation(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmpdir.name, "corr_alerts.db")
        self._old_db_file = alert_store_mod.DB_FILE
        alert_store_mod.DB_FILE = self.db_path

    def tearDown(self):
        alert_store_mod.DB_FILE = self._old_db_file
        self._tmpdir.cleanup()

    def test_1_syn_flood_and_ml_same_window_same_attacker(self):
        """SYN_FLOOD + ML_ANOMALY in the same window keep SYN_FLOOD primary with ML evidence."""
        corr = IncidentCorrelator()
        res = corr.correlate(
            detections={"10.10.10.10": [_syn_flood_det(), _ml_det(0.32)]},
            communication_context=_comm_ctx("10.10.10.10", "10.10.10.20"),
            timestamp=100.0,
        )
        out = res["10.10.10.10"]
        self.assertEqual([d.attack_type for d in out], ["SYN_FLOOD"])
        self.assertEqual(out[0].confidence, 1.0)
        self.assertTrue(any("ML corroboration: 32%" in r for r in out[0].reasons))
        self.assertTrue(any("ML evidence:" in r for r in out[0].reasons))

    def test_2_syn_flood_and_ml_different_consecutive_windows_same_attacker(self):
        """ML_ANOMALY for the same attacker in the next window enriches active SYN_FLOOD, not a duplicate alert."""
        corr = IncidentCorrelator(correlation_window=15.0)
        mgr = AlertManager(resolve_after=300.0, db_path=self.db_path)
        ctx = _comm_ctx("10.10.10.10", "10.10.10.20")

        win1 = corr.correlate({"10.10.10.10": [_syn_flood_det()]}, ctx, timestamp=100.0)
        for src, dets in win1.items():
            mgr.process(src, dets, timestamp=100.0, communication_context=ctx.get(src))

        win2 = corr.correlate({"10.10.10.10": [_ml_det(0.30)]}, ctx, timestamp=101.0)
        self.assertEqual([d.attack_type for d in win2["10.10.10.10"]], ["SYN_FLOOD"])
        for src, dets in win2.items():
            mgr.process(src, dets, timestamp=101.0, communication_context=ctx.get(src))

        active = mgr.active_alerts()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].attack_type, "SYN_FLOOD")
        self.assertEqual(active[0].source_ip, "10.10.10.10")
        self.assertEqual(active[0].confidence, 1.0)
        self.assertEqual(active[0].severity, "HIGH")
        self.assertTrue(any("high SYN rate" in r for r in active[0].reasons))
        self.assertTrue(any("ML corroboration: 30%" in r for r in active[0].reasons))

    def test_3_victim_ml_anomaly_attached_same_and_cross_window(self):
        """Victim responder ML_ANOMALY is attached to attacker's SYN_FLOOD in both same & next windows."""
        corr = IncidentCorrelator(correlation_window=15.0)
        mgr = AlertManager(resolve_after=300.0, db_path=self.db_path)
        ctx = _comm_ctx("10.10.10.10", "10.10.10.20")

        # Window 1: SYN_FLOOD(10.10.10.10) + victim ML_ANOMALY(10.10.10.20)
        win1 = corr.correlate(
            {"10.10.10.10": [_syn_flood_det()], "10.10.10.20": [_ml_det(0.34, ["packets_per_second high"])]},
            ctx,
            timestamp=100.0,
        )
        self.assertEqual(win1["10.10.10.20"], [])
        self.assertTrue(any("Victim-side ML impact anomaly: 34%" in r for r in win1["10.10.10.10"][0].reasons))
        for src, dets in win1.items():
            mgr.process(src, dets, timestamp=100.0, communication_context=ctx.get(src))

        # Window 2: only victim 10.10.10.20 emits lingering SYN+ACK ML_ANOMALY
        victim_only_ctx = {"10.10.10.20": ctx["10.10.10.20"]}
        win2 = corr.correlate(
            {"10.10.10.20": [_ml_det(0.38, ["outbound_inbound_ratio=800"])]},
            victim_only_ctx,
            timestamp=101.0,
        )
        self.assertEqual(win2["10.10.10.20"], [])
        self.assertEqual([d.attack_type for d in win2["10.10.10.10"]], ["SYN_FLOOD"])
        self.assertTrue(any("Victim-side ML impact anomaly: 38%" in r for r in win2["10.10.10.10"][0].reasons))
        for src, dets in win2.items():
            mgr.process(src, dets, timestamp=101.0, communication_context=victim_only_ctx.get(src))

        active = mgr.active_alerts()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].source_ip, "10.10.10.10")
        self.assertEqual(active[0].attack_type, "SYN_FLOOD")
        self.assertEqual(active[0].responder_ips, ["10.10.10.20"])

    def test_4_unrelated_ml_anomaly_remains_independent(self):
        """An ML_ANOMALY on an unrelated source must remain independently reportable."""
        corr = IncidentCorrelator(correlation_window=15.0)
        ctx = _comm_ctx("10.10.10.10", "10.10.10.20")
        win1 = corr.correlate(
            {"10.10.10.10": [_syn_flood_det()], "10.10.10.99": [_ml_det(0.41)]},
            ctx,
            timestamp=100.0,
        )
        self.assertEqual([d.attack_type for d in win1["10.10.10.99"]], ["ML_ANOMALY"])
        self.assertEqual(win1["10.10.10.99"][0].confidence, 0.41)

    def test_5_unrelated_responder_ml_anomaly_not_attached(self):
        """An ML_ANOMALY on a responder to another flow must NOT attach to an unrelated attack."""
        corr = IncidentCorrelator(correlation_window=15.0)
        ctx = _comm_ctx("10.10.10.10", "10.10.10.20")
        other_flow = {
            "flow_id": "10.10.10.99:50000<->10.10.10.30:443/TCP",
            "protocol": "TCP",
            "src_ip": "10.10.10.99",
            "dst_ip": "10.10.10.30",
            "src_port": 50000,
            "dst_port": 443,
            "initiator_ip": "10.10.10.99",
            "responder_ip": "10.10.10.30",
        }
        ctx["10.10.10.30"] = {
            "source_ip": "10.10.10.30",
            "initiator_ip": None,
            "responder_ips": [],
            "observed_peers": ["10.10.10.99"],
            "related_flows": [other_flow],
        }
        win1 = corr.correlate(
            {"10.10.10.10": [_syn_flood_det()], "10.10.10.30": [_ml_det(0.45)]},
            ctx,
            timestamp=100.0,
        )
        self.assertEqual([d.attack_type for d in win1["10.10.10.30"]], ["ML_ANOMALY"])
        self.assertFalse(any("Victim-side" in r for r in win1["10.10.10.10"][0].reasons))

    def test_6_normal_window_does_not_inherit_stale_correlation(self):
        """Normal traffic emits no alerts and stale episodes expire after correlation_window."""
        corr = IncidentCorrelator(correlation_window=15.0)
        ctx = _comm_ctx("10.10.10.10", "10.10.10.20")

        corr.correlate({"10.10.10.10": [_syn_flood_det()]}, ctx, timestamp=100.0)

        # Normal window right after attack: empty detections must stay empty
        normal = corr.correlate({"10.10.10.10": [], "10.10.10.20": []}, ctx, timestamp=102.0)
        self.assertEqual(normal["10.10.10.10"], [])
        self.assertEqual(normal["10.10.10.20"], [])

        # Past correlation_window (t=120.0 > 100.0 + 15.0): new ML_ANOMALY is independent
        later = corr.correlate({"10.10.10.10": [_ml_det(0.33)]}, ctx, timestamp=120.0)
        self.assertEqual([d.attack_type for d in later["10.10.10.10"]], ["ML_ANOMALY"])

    def test_7_port_scan_correlation_remains_functional(self):
        """PORT_SCAN + strong SYN_FLOOD + same/cross-window ML remain correlated under PORT_SCAN."""
        corr = IncidentCorrelator(correlation_window=15.0)
        ctx = _comm_ctx("10.10.10.10", "10.10.10.20")
        src_feat = {
            "10.10.10.10": {
                "unique_destination_ports": 25,
                "ports_per_destination": 25.0,
                "unique_destinations": 1,
            }
        }
        win1 = corr.correlate(
            detections={
                "10.10.10.10": [_port_scan_det(), _syn_flood_det(), _ml_det(0.36)],
                "10.10.10.20": [_ml_det(0.31, ["packets_per_second high"])],
            },
            communication_context=ctx,
            source_features=src_feat,
            timestamp=200.0,
        )
        self.assertEqual([d.attack_type for d in win1["10.10.10.10"]], ["PORT_SCAN"])
        reasons = win1["10.10.10.10"][0].reasons
        self.assertTrue(any("SYN activity correlated" in r for r in reasons))
        self.assertTrue(any("ML corroboration: 36%" in r for r in reasons))
        self.assertTrue(any("Victim-side ML impact anomaly: 31%" in r for r in reasons))
        self.assertEqual(win1["10.10.10.20"], [])

    def test_end_to_end_pipeline_syn_flood_single_incident(self):
        """Full PacketPipeline splits SYN flood across 1s windows + SA replies into 1 SYN_FLOOD alert."""
        pipeline = PacketPipeline(use_ml=True, record_metrics=False)
        t0 = 1000.0

        # Window 1 (peak SYN_FLOOD: 96 SYNs + SA)
        for i in range(96):
            pkt = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=40000 + i, dport=80, flags="S")
            pkt.time = t0 + 0.70 + i * 0.008
            pipeline.process_packet(pkt)
            rep = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(sport=80, dport=40000 + i, flags="SA")
            rep.time = pkt.time + 0.001
            pipeline.process_packet(rep)

        # Window 2 (tail ramp-down: 30 SYNs -> ML_ANOMALY only for 10.10.10.10)
        for i in range(30):
            pkt = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=42000 + i, dport=80, flags="S")
            pkt.time = t0 + 2.05 + i * 0.01
            pipeline.process_packet(pkt)
            rep = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(sport=80, dport=42000 + i, flags="SA")
            rep.time = pkt.time + 0.001
            pipeline.process_packet(rep)

        # Window 3 (lingering SA retries from victim 10.10.10.20 must never spawn an independent victim alert)
        for i in range(20):
            rep = IP(src="10.10.10.20", dst="10.10.10.10") / TCP(sport=80, dport=42000 + i, flags="SA")
            rep.time = t0 + 3.10 + i * 0.01
            pipeline.process_packet(rep)

        pipeline.flush_if_ready(t0 + 5.0)
        active = pipeline.alert_manager.active_alerts()
        self.assertEqual(len(active), 1, f"Expected single SYN_FLOOD alert, got {[a.to_dict() for a in active]}")
        self.assertEqual(active[0].attack_type, "SYN_FLOOD")
        self.assertEqual(active[0].source_ip, "10.10.10.10")
        self.assertEqual(active[0].responder_ips, ["10.10.10.20"])
        self.assertTrue(any("ML corroboration:" in r for r in active[0].reasons))

    def test_precursor_ml_alert_absorbed_when_syn_flood_confirms(self):
        """Precursor ML_ANOMALY in ramp-up window is folded and resolved when SYN_FLOOD triggers."""
        pipeline = PacketPipeline(use_ml=True, record_metrics=False)
        t0 = 2000.0

        # Window 1: 30 SYNs (< 50 SYN_FLOOD threshold) -> triggers ML_ANOMALY first
        for i in range(30):
            pkt = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=43000 + i, dport=80, flags="S")
            pkt.time = t0 + 0.10 + i * 0.01
            pipeline.process_packet(pkt)

        # Window 2: 90 SYNs -> triggers SYN_FLOOD
        for i in range(90):
            pkt = IP(src="10.10.10.10", dst="10.10.10.20") / TCP(sport=44000 + i, dport=80, flags="S")
            pkt.time = t0 + 1.10 + i * 0.008
            pipeline.process_packet(pkt)

        pipeline.flush_if_ready(t0 + 3.0)
        active = pipeline.alert_manager.active_alerts()
        self.assertEqual(len(active), 1, f"Expected absorbed single active SYN_FLOOD, got {[a.to_dict() for a in active]}")
        self.assertEqual(active[0].attack_type, "SYN_FLOOD")
        self.assertEqual(active[0].source_ip, "10.10.10.10")


if __name__ == "__main__":
    unittest.main()
