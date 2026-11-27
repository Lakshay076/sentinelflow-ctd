"""
Regression tests covering Phase 1-3 fixes:
1. Replay isolation: API simulation state cannot contaminate subsequent PCAP replay,
   and replay does not reset or disturb a concurrently active live_pipeline.
2. Validation scoping & FP reporting: validate() scopes to the latest replay run
   and separates alert-level vs unique-IP false positive counts.
3. End-to-end verification on test_api.pcap (if present): benign 10.0.0.17
   produces zero FPs while expected PORT_SCAN & SYN_FLOOD are caught.
4. ML inference parity: single-pass decision_function and batch scoring match
   predict() + decision_function() semantics identically.
"""

import json
import os
import tempfile
import unittest

from scapy.all import IP, TCP, Raw

from alerts.alert_store import AlertStore
from collector import packet_collector as collector
from collector.pcap_replay_collector import replay
from demo.simulator import run_demo_simulation
from detectors.detector_engine import DetectorEngine
from features.feature_context import FeatureContext
from inference.feature_schema import features_to_vector
from inference import ml_detector
from inference.ml_detector import detect_ml_anomalies_batch, detect_ml_anomaly
from scripts.validate_detections import validate


class TestRegressionFixes(unittest.TestCase):

    def test_ml_single_and_batch_decision_parity(self):
        """Single-score and batch ML detection must match sklearn predict() + decision_function()."""
        ml_detector._try_load()
        self.assertIsNotNone(ml_detector._model, "Trained model.joblib must be present")

        samples = [
            # Below activity gate -> inactive
            {"packets": 2, "bytes": 120, "active_flows": 1},
            # Normal web browsing -> benign
            {
                "packets": 20,
                "bytes": 4000,
                "bytes_received": 16000,
                "packets_per_second": 3.0,
                "bytes_per_second": 500.0,
                "syn_packet_ratio": 0.05,
                "unique_destinations": 2,
                "unique_destination_ports": 2,
                "active_flows": 2,
                "flows_per_second": 2.0,
                "outbound_inbound_ratio": 0.25,
            },
            # Strong port scan / flood outlier -> anomaly
            {
                "packets": 400,
                "bytes": 24000,
                "bytes_received": 0,
                "packets_per_second": 400.0,
                "bytes_per_second": 24000.0,
                "syn_packet_ratio": 0.95,
                "unique_destinations": 60,
                "unique_destination_ports": 60,
                "active_flows": 60,
                "flows_per_second": 60.0,
                "outbound_inbound_ratio": 500.0,
            },
            # 10.0.0.17 with fixed TLS default (no 999.0 sentinel)
            {
                "packets": 4,
                "bytes": 818,
                "bytes_received": 0,
                "packets_per_second": 4.0,
                "bytes_per_second": 818.0,
                "syn_packet_ratio": 0.25,
                "unique_destinations": 1,
                "unique_destination_ports": 1,
                "active_flows": 4,
                "flows_per_second": 4.0,
                "outbound_inbound_ratio": 818.0,
            },
        ]

        batch_results = detect_ml_anomalies_batch(samples)
        self.assertEqual(len(batch_results), len(samples))

        for sample, batch_res in zip(samples, batch_results):
            single_res = detect_ml_anomaly(sample)
            self.assertEqual(batch_res.detected, single_res.detected)
            self.assertEqual(batch_res.severity, single_res.severity)
            self.assertEqual(batch_res.score, single_res.score)
            self.assertAlmostEqual(batch_res.confidence, single_res.confidence, places=6)
            self.assertEqual(batch_res.reasons, single_res.reasons)

            # Verify exact parity with legacy predict() == -1 and decision_function() < -0.04
            if ml_detector._is_active_for_ml(sample):
                vec = features_to_vector(sample)
                pred = int(ml_detector._model.predict([vec])[0])
                score = float(ml_detector._model.decision_function([vec])[0])
                expected_detected = (pred == -1) and (score < -0.04)
                self.assertEqual(single_res.detected, expected_detected)

    def test_detector_engine_batch_matches_single_analyze(self):
        """DetectorEngine.analyze_context() batched ML must match analyze() per source."""
        engine = DetectorEngine(use_ml=True)
        sources = {
            "10.0.0.1": {
                "packets": 10,
                "bytes": 1500,
                "packets_per_second": 10.0,
                "bytes_per_second": 1500.0,
                "syn_packet_ratio": 0.1,
                "unique_destinations": 1,
                "unique_destination_ports": 1,
                "active_flows": 1,
                "flows_per_second": 1.0,
                "outbound_inbound_ratio": 0.5,
            },
            "10.0.0.2": {
                "packets": 500,
                "bytes": 30000,
                "packets_per_second": 500.0,
                "bytes_per_second": 30000.0,
                "syn_packet_ratio": 1.0,
                "unique_destinations": 1,
                "unique_destination_ports": 50,
                "active_flows": 500,
                "flows_per_second": 500.0,
                "outbound_inbound_ratio": 30000.0,
            },
        }
        ctx = FeatureContext(network={"packets": 510, "bytes": 31500}, sources=sources)
        ctx_results = engine.analyze_context(ctx)

        for sip, feat in sources.items():
            single_types = [(r.attack_type, round(r.confidence, 4)) for r in engine.analyze(feat)]
            ctx_types = [(r.attack_type, round(r.confidence, 4)) for r in ctx_results[sip]]
            self.assertEqual(ctx_types, single_types)

    def test_api_simulation_does_not_contaminate_pcap_replay_or_live_pipeline(self):
        """
        API simulation of DATA_EXFILTRATION (10.10.10.10) must not leak into a
        subsequent PCAP replay, and PCAP replay must not reset live_pipeline.
        """
        pcap_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "test_api.pcap",
        )
        gt_path = pcap_path + ".ground_truth.json"
        if not (os.path.exists(pcap_path) and os.path.exists(gt_path)):
            self.skipTest("test_api.pcap not present in workspace")

        # Seed live_pipeline with a dummy packet to ensure replay does not reset it.
        collector.live_pipeline.reset()
        live_pkt = IP(src="10.88.88.88", dst="10.88.88.89") / TCP(sport=12345, dport=80, flags="A")
        live_pkt.time = 1000.0
        collector.process_packet(live_pkt)
        self.assertEqual(len(collector.live_pipeline.flow_engine.flows), 1)

        # Run DATA_EXFILTRATION API simulation on 10.10.10.10 right before PCAP replay
        sim_res = run_demo_simulation("DATA_EXFILTRATION", source_ip="10.10.10.10", target_ip="10.10.10.20")
        self.assertTrue(sim_res["detected"])

        # Resolve active alerts cleanly before replaying
        store = AlertStore()
        for a in store.active():
            store.resolve(a.alert_id, timestamp=a.last_seen + 1.0)

        benchmark = replay(pcap_path=pcap_path, max_speed=True)
        self.assertEqual(benchmark["packet_count"], 445)

        # Live pipeline state must remain untouched by both simulation and replay.
        self.assertEqual(len(collector.live_pipeline.flow_engine.flows), 1)

        # Replay must not emit a DATA_EXFILTRATION carryover alert for 10.10.10.10
        replay_alerts = store.get_many(benchmark["alert_ids"])
        self.assertFalse(
            any(a.source_ip == "10.10.10.10" and a.attack_type == "DATA_EXFILTRATION" for a in replay_alerts),
            "API simulation DATA_EXFILTRATION leaked into subsequent PCAP replay!",
        )

        # Benign 10.0.0.17 must produce ZERO alerts in this replay
        self.assertFalse(
            any(a.source_ip == "10.0.0.17" for a in replay_alerts),
            f"Benign 10.0.0.17 produced false positives: {[a.to_dict() for a in replay_alerts if a.source_ip == '10.0.0.17']}",
        )

        report = validate(gt_path, alert_ids=benchmark["alert_ids"])
        self.assertEqual(report["true_positives"], 2)
        self.assertEqual(report["false_negatives"], 0)
        self.assertEqual(report["false_positive_alerts"], 0)
        self.assertEqual(report["false_positive_ips"], 0)
        self.assertEqual(report["precision"], 1.0)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["f1"], 1.0)

    def test_ml_uses_same_window_observed_destinations_without_affecting_scans(self):
        """Non-SYN TCP traffic in a 1s slice keeps unique_destinations=0 for scans but avoids z=-5.4 ML FP."""
        from features.source_aggregation import SourceAggregator
        from detectors.scan_detector import detect_port_scan

        agg = SourceAggregator()
        agg.add_packet(
            src_ip="10.0.0.17",
            dst_ip="203.0.113.8",
            protocol="TCP",
            packet_bytes=377,
            src_port=40849,
            dst_port=443,
            tcp_syn=False,
            tcp_ack=True,
        )
        agg.add_packet(
            src_ip="10.0.0.17",
            dst_ip="203.0.113.32",
            protocol="TCP",
            packet_bytes=372,
            src_port=40861,
            dst_port=443,
            tcp_syn=False,
            tcp_ack=True,
        )
        feat = agg.get_features(duration=1.0)["10.0.0.17"]
        feat["dns_queries_per_second"] = 0.2
        self.assertEqual(feat["unique_destinations"], 0)
        self.assertEqual(feat["observed_unique_destinations"], 2)
        self.assertFalse(detect_port_scan(feat).detected)
        self.assertFalse(detect_ml_anomaly(feat).detected)

    def test_validate_reports_both_alert_and_ip_precision(self):
        """Multiple alerts for one benign IP must be explicitly separated into alert-level vs IP-level FP counts."""
        store = AlertStore()
        a1 = store.create("10.0.0.50", "PORT_SCAN", "HIGH", 0.9, 100.0, ["scan"])
        fp1 = store.create("10.0.0.17", "PORT_SCAN", "HIGH", 1.0, 100.0, ["fp1"])
        fp2 = store.create("10.0.0.17", "ML_ANOMALY", "LOW", 0.3, 100.0, ["fp2"])

        gt = {
            "pcap_file": "unit_test_dummy.pcap",
            "expected_detections": [{"source_ip": "10.0.0.50", "attack_type": "PORT_SCAN"}],
            "benign_ips": ["10.0.0.17"],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(gt, tf)
            gt_path = tf.name

        try:
            report = validate(gt_path, alert_ids=[a1.alert_id, fp1.alert_id, fp2.alert_id])
            self.assertEqual(report["true_positives"], 1)
            self.assertEqual(report["false_positive_alerts"], 2)
            self.assertEqual(report["false_positive_ips"], 1)
            self.assertAlmostEqual(report["alert_precision"], 1.0 / 3.0, places=4)
            self.assertAlmostEqual(report["ip_precision"], 0.5, places=4)
        finally:
            os.remove(gt_path)


if __name__ == "__main__":
    unittest.main()
