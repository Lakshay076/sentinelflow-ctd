import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock

import joblib
import numpy as np
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw
from scapy.utils import PcapReader, PcapWriter
from sklearn.ensemble import IsolationForest

from detectors.detector_engine import DetectorEngine
from detectors.tls_detector import detect_tls_anomaly
from flow.flow_engine import FlowEngine
from collector import packet_collector
from collector.packet_record import PacketRecord
from features.feature_context import FeatureContext
from features.communication_context import CommunicationContext
from features.window import WindowManager
from features.security_features import calculate_security_features
from features.source_aggregation import SourceAggregator
from features.tls_tracker import TLSTracker
from features.behavior_window import BehaviorWindow
from features.beacon_tracker import BeaconTracker
from features.dns_tracker import DNSTracker
from inference.train_model_from_pcap import extract_training_vectors
from inference.feature_schema import (
    FEATURE_NAMES,
    DEFAULT_VALUES,
    features_to_vector,
    is_dns_flow,
    should_track_beacon_flow,
)
import inference.ml_detector as ml
import inference.train_model_from_pcap as trainer


class TestIsolationForestParity(unittest.TestCase):

    def setUp(self):
        self.original_model_path = ml.MODEL_PATH
        self.original_stats_path = ml.STATS_PATH
        ml._model = None
        ml._stats = None
        ml._load_attempted = False
        ml._warned_missing = False

    def tearDown(self):
        ml.MODEL_PATH = self.original_model_path
        ml.STATS_PATH = self.original_stats_path
        ml._model = None
        ml._stats = None
        ml._load_attempted = False
        ml._warned_missing = False

    def test_feature_schema_length_and_defaults(self):
        self.assertEqual(len(FEATURE_NAMES), 16)
        vector = features_to_vector({"packets_per_second": None})
        self.assertEqual(len(vector), 16)
        self.assertEqual(vector[0], DEFAULT_VALUES["packets_per_second"])
        self.assertEqual(vector[-2], DEFAULT_VALUES["tls_avg_cipher_count"])

    def test_flow_direction_is_attributed_to_initiator(self):
        engine = FlowEngine()
        syn = PacketRecord(
            timestamp=100.0,
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            protocol="TCP",
            packet_length=60,
            src_port=50000,
            dst_port=443,
            tcp_flags="S",
        )
        syn_flow = engine.process_packet(syn)
        self.assertEqual(syn_flow.initiator_ip, "10.0.0.1")
        self.assertEqual(syn_flow.responder_ip, "8.8.8.8")

        syn_ack = PacketRecord(
            timestamp=100.01,
            src_ip="8.8.8.8",
            dst_ip="10.0.0.1",
            protocol="TCP",
            packet_length=60,
            src_port=443,
            dst_port=50000,
            tcp_flags="SA",
        )
        syn_ack_flow = engine.process_packet(syn_ack)
        self.assertEqual(syn_ack_flow.initiator_ip, "10.0.0.1")
        self.assertEqual(syn_ack_flow.responder_ip, "8.8.8.8")

        aggregator = SourceAggregator()
        aggregator.add_packet(
            src_ip=syn.src_ip,
            dst_ip=syn.dst_ip,
            protocol=syn.protocol,
            packet_bytes=syn.packet_length,
            src_port=syn.src_port,
            dst_port=syn.dst_port,
            tcp_syn=True,
            initiator_ip=syn_flow.initiator_ip,
            responder_ip=syn_flow.responder_ip,
        )
        aggregator.add_packet(
            src_ip=syn_ack.src_ip,
            dst_ip=syn_ack.dst_ip,
            protocol=syn_ack.protocol,
            packet_bytes=syn_ack.packet_length,
            src_port=syn_ack.src_port,
            dst_port=syn_ack.dst_port,
            tcp_syn=True,
            tcp_ack=True,
            initiator_ip=syn_ack_flow.initiator_ip,
            responder_ip=syn_ack_flow.responder_ip,
        )
        features = aggregator.get_features(1.0)
        self.assertEqual(features["10.0.0.1"]["tcp_syn"], 1)
        self.assertEqual(features["10.0.0.1"]["active_flows"], 1)
        self.assertEqual(features["8.8.8.8"]["tcp_syn"], 0)

    def test_dns_flows_share_beacon_exclusion(self):
        self.assertTrue(is_dns_flow(53, 53000))
        self.assertTrue(is_dns_flow(53000, 53))
        self.assertFalse(should_track_beacon_flow(True, 53, 53000))
        self.assertTrue(should_track_beacon_flow(True, 50000, 443))

    def test_tls_missing_values_are_not_extreme(self):
        tracker = TLSTracker()
        tracker.add_splt_packet(10.0, "10.0.0.1", 120)
        features = tracker.get_features(11.0)["10.0.0.1"]
        self.assertEqual(features["tls_avg_cipher_count"], 20.0)
        self.assertEqual(features["tls_avg_extension_count"], 20.0)
        self.assertEqual(features["tls_missing_sni_ratio"], 0.0)

    def test_tls_unavailable_metadata_does_not_trigger_rule_detector(self):
        unavailable_tls = {
            "tls_client_hello_count": 0,
            "tls_avg_cipher_count": 20.0,
            "tls_avg_extension_count": 20.0,
            "tls_missing_sni_ratio": 0.0,
            "quic_packet_count": 0,
            "splt_packet_count": 0,
        }

        # 20.0 and 0.0 are neutral schema imputations for unobserved
        # TLS metadata, not measured cipher counts or proof of missing SNI.
        result = detect_tls_anomaly(unavailable_tls)
        self.assertFalse(result.detected)

    def _set_mock_model(self, prediction=-1, score=-0.10):
        model = MagicMock()
        model.n_features_in_ = len(FEATURE_NAMES)
        model.predict.return_value = [prediction]
        model.decision_function.return_value = [score]
        ml._model = model
        ml._stats = {
            name: {"mean": 0.0, "std": 1.0}
            for name in FEATURE_NAMES
        }
        ml._load_attempted = True
        return model

    def test_normal_traffic_reaches_model(self):
        model = self._set_mock_model(prediction=1, score=-0.01)
        ml.detect_ml_anomaly({
            "packets_per_second": 3.0,
            "bytes_per_second": 500.0,
            "active_flows": 2,
            "flows_per_second": 2.0,
        })
        model.predict.assert_called_once()
        model.decision_function.assert_called_once()

    def test_suspicious_traffic_reaches_model(self):
        model = self._set_mock_model(prediction=-1, score=-0.10)
        result = ml.detect_ml_anomaly({
            "packets_per_second": 400.0,
            "bytes_per_second": 900.0,
            "active_flows": 60,
            "flows_per_second": 60.0,
        })
        model.predict.assert_called_once()
        model.decision_function.assert_called_once()
        self.assertTrue(result.detected)

    def test_idle_traffic_is_handled_separately(self):
        model = self._set_mock_model(prediction=-1, score=-0.10)
        result = ml.detect_ml_anomaly({
            "packets_per_second": 0.1,
            "bytes_per_second": 20.0,
            "active_flows": 0,
            "flows_per_second": 0.0,
        })
        model.predict.assert_not_called()
        model.decision_function.assert_not_called()
        self.assertFalse(result.detected)

    def test_one_packet_negligible_traffic_is_idle(self):
        model = self._set_mock_model(prediction=-1, score=-0.10)
        result = ml.detect_ml_anomaly({
            "packets_per_second": 1.0,
            "bytes_per_second": 60.0,
            "active_flows": 0,
            "flows_per_second": 0.0,
        })
        model.predict.assert_not_called()
        model.decision_function.assert_not_called()
        self.assertFalse(result.detected)

    def test_one_active_flow_negligible_traffic_is_idle(self):
        model = self._set_mock_model(prediction=-1, score=-0.10)
        result = ml.detect_ml_anomaly({
            "packets_per_second": 2.0,
            "bytes_per_second": 120.0,
            "active_flows": 1,
            "flows_per_second": 1.0,
        })
        model.predict.assert_not_called()
        model.decision_function.assert_not_called()
        self.assertFalse(result.detected)

    def test_one_dns_query_negligible_traffic_is_idle(self):
        model = self._set_mock_model(prediction=-1, score=-0.10)
        result = ml.detect_ml_anomaly({
            "packets_per_second": 2.0,
            "bytes_per_second": 160.0,
            "active_flows": 1,
            "flows_per_second": 1.0,
            "dns_query_count": 1,
        })
        model.predict.assert_not_called()
        model.decision_function.assert_not_called()
        self.assertFalse(result.detected)

    def test_genuinely_active_traffic_reaches_model(self):
        model = self._set_mock_model(prediction=1, score=-0.01)
        result = ml.detect_ml_anomaly({
            "packets_per_second": 5.0,
            "bytes_per_second": 500.0,
            "active_flows": 3,
            "flows_per_second": 3.0,
            "dns_query_count": 2,
            "tls_client_hello_count": 1,
        })
        model.predict.assert_called_once()
        model.decision_function.assert_called_once()
        self.assertFalse(result.detected)

    def test_idle_guard_treats_non_finite_values_as_defaults(self):
        non_finite_values = (float("nan"), float("inf"), float("-inf"))
        for value in non_finite_values:
            with self.subTest(value=value):
                model = self._set_mock_model(prediction=-1, score=-0.10)
                result = ml.detect_ml_anomaly({
                    "packets_per_second": value,
                    "bytes_per_second": 20.0,
                    "active_flows": 0,
                    "flows_per_second": 0.0,
                    "dns_query_count": 0,
                    "tls_client_hello_count": 0,
                })
                model.predict.assert_not_called()
                model.decision_function.assert_not_called()
                self.assertFalse(result.detected)

    def test_explanations_keep_near_constant_features_out_of_z_ranking(self):
        stats = {
            name: {"mean": 0.0, "std": 1.0}
            for name in FEATURE_NAMES
        }
        near_constant_name = "dns_high_entropy_ratio"
        stats[near_constant_name] = {"mean": 0.0, "std": 0.0}
        vector = [0.0] * len(FEATURE_NAMES)
        vector[FEATURE_NAMES.index(near_constant_name)] = 0.5

        reasons = ml._explain(vector, stats)

        near_constant_reason = next(
            reason for reason in reasons if near_constant_name in reason
        )
        self.assertIn("near-constant baseline", near_constant_reason)
        self.assertNotIn("z-score", near_constant_reason)
        self.assertNotIn("standardized-deviation", near_constant_reason)

    @staticmethod
    def _build_client_hello():
        ciphers = [0x1301, 0x1302, 0xc02b]
        cipher_bytes = b"".join(c.to_bytes(2, "big") for c in ciphers)
        sni = b"example.test"
        sni_data = (
            (len(sni) + 3).to_bytes(2, "big")
            + b"\x00"
            + len(sni).to_bytes(2, "big")
            + sni
        )
        ext = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
        ext_len = len(ext).to_bytes(2, "big")
        handshake_body = (
            b"\x03\x03"
            + b"\x11" * 32
            + b"\x00"
            + len(cipher_bytes).to_bytes(2, "big")
            + cipher_bytes
            + b"\x01\x00"
            + ext_len
            + ext
        )
        handshake_header = b"\x01" + len(handshake_body).to_bytes(3, "big")
        record_header = b"\x16\x03\x03" + len(handshake_header + handshake_body).to_bytes(2, "big")
        return record_header + handshake_header + handshake_body

    def test_training_and_live_feature_parity_for_controlled_pcap(self):
        packets = []

        def add(packet, timestamp):
            packet.time = timestamp
            packets.append(packet)

        client_ip = "10.0.0.1"
        server_ip = "203.0.113.10"
        add(IP(src=client_ip, dst=server_ip) / TCP(sport=50000, dport=443, flags="S"), 100.0)
        add(IP(src=server_ip, dst=client_ip) / TCP(sport=443, dport=50000, flags="SA"), 100.1)
        add(
            IP(src=client_ip, dst=server_ip)
            / TCP(sport=50000, dport=443, flags="A")
            / Raw(load=self._build_client_hello()),
            100.2,
        )
        add(
            IP(src=client_ip, dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.test")),
            100.3,
        )
        add(
            IP(src="8.8.8.8", dst=client_ip)
            / UDP(sport=53, dport=53000)
            / DNS(qr=1),
            100.4,
        )
        quic_payload = b"\xc0\x00\x00\x00\x01\x00\x00"
        add(
            IP(src=client_ip, dst=server_ip)
            / UDP(sport=51000, dport=443)
            / Raw(load=quic_payload),
            100.5,
        )
        add(IP(src=client_ip, dst=server_ip) / TCP(sport=50000, dport=443, flags="A"), 101.1)

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_path = os.path.join(temp_dir, "feature-parity.pcap")
            writer = PcapWriter(pcap_path)
            for packet in packets:
                writer.write(packet)
            writer.close()

            training_records = []
            training_matrix = extract_training_vectors(
                pcap_path,
                capture_records=training_records,
            )

            live_vectors = []

            original_globals = {
                "flow_engine": packet_collector.flow_engine,
                "window_manager": packet_collector.window_manager,
                "source_aggregator": packet_collector.source_aggregator,
                "communication_context": packet_collector.communication_context,
                "behavior_window": packet_collector.behavior_window,
                "beacon_tracker": packet_collector.beacon_tracker,
                "dns_tracker": packet_collector.dns_tracker,
                "tls_tracker": packet_collector.tls_tracker,
                "evaluate_window": packet_collector.evaluate_window,
            }

            packet_collector.flow_engine = FlowEngine(timeout=60)
            packet_collector.window_manager = WindowManager(window_seconds=1.0)
            packet_collector.source_aggregator = SourceAggregator()
            packet_collector.communication_context = CommunicationContext()
            packet_collector.behavior_window = BehaviorWindow(window_seconds=10.0)
            packet_collector.beacon_tracker = BeaconTracker(window_seconds=300.0)
            packet_collector.dns_tracker = DNSTracker(window_seconds=30.0)
            packet_collector.tls_tracker = TLSTracker(window_seconds=300.0)

            def capture_live_window(window_features, source_features, timestamp, communication_features=None):
                security_features = calculate_security_features(window_features)
                context = FeatureContext(
                    network=window_features,
                    security=security_features,
                    sources=source_features,
                    behavior=packet_collector.behavior_window.get_source_features(current_timestamp=timestamp),
                    beacon=packet_collector.beacon_tracker.get_features(current_timestamp=timestamp),
                    dns=packet_collector.dns_tracker.get_features(current_timestamp=timestamp),
                    tls=packet_collector.tls_tracker.get_features(current_timestamp=timestamp),
                    communication=communication_features or [],
                )
                for source_ip in context.source_ips():
                    live_vectors.append({
                        "source_ip": source_ip,
                        "window_timestamp": float(timestamp),
                        "window_start": float(
                            timestamp - window_features["window_duration"]
                        ),
                        "features": dict(context.get_combined_source_features(source_ip)),
                    })

            packet_collector.evaluate_window = capture_live_window

            try:
                with PcapReader(pcap_path) as reader:
                    for packet in reader:
                        packet_collector.process_packet(packet)
            finally:
                for name, original in original_globals.items():
                    setattr(packet_collector, name, original)

            def record_key(record):
                return (
                    record["source_ip"],
                    round(float(record["window_start"]), 6),
                )

            training_by_source_window = {}
            training_duplicate_keys = set()
            for record in training_records:
                key = record_key(record)
                if key in training_by_source_window:
                    training_duplicate_keys.add(key)
                else:
                    training_by_source_window[key] = record["features"]

            live_by_source_window = {}
            live_duplicate_keys = set()
            for live_record in live_vectors:
                key = record_key(live_record)
                if key in live_by_source_window:
                    live_duplicate_keys.add(key)
                else:
                    live_by_source_window[key] = live_record["features"]

            self.assertFalse(
                training_duplicate_keys,
                msg=f"Duplicate training source/window records: {sorted(training_duplicate_keys)}",
            )
            self.assertFalse(
                live_duplicate_keys,
                msg=f"Duplicate live source/window records: {sorted(live_duplicate_keys)}",
            )

            training_keys = set(training_by_source_window)
            live_keys = set(live_by_source_window)
            self.assertEqual(
                live_keys - training_keys,
                set(),
                msg="Live source/window records missing from training",
            )
            self.assertEqual(
                training_keys - live_keys,
                set(),
                msg="Training source/window records missing from live",
            )
            self.assertTrue(
                training_keys,
                msg="The parity PCAP produced no training source/window records",
            )

            for key in sorted(training_keys):
                training_features = training_by_source_window[key]
                live_features = live_by_source_window[key]
                training_vector = features_to_vector(training_features)
                live_vector = features_to_vector(live_features)
                self.assertEqual(
                    len(training_vector),
                    len(FEATURE_NAMES),
                )
                self.assertEqual(len(live_vector), len(FEATURE_NAMES))
                for index, feature_name in enumerate(FEATURE_NAMES):
                    self.assertEqual(
                        live_vector[index],
                        training_vector[index],
                        msg=(
                            f"Parity mismatch for source={key[0]}, "
                            f"window={key[1]}, feature={feature_name}"
                        ),
                    )
            
            self.assertEqual(training_matrix.shape[1], len(FEATURE_NAMES))

    def test_missing_model_artifact_does_not_crash(self):
        ml.MODEL_PATH = os.path.join(tempfile.gettempdir(), "missing_ctd_model.joblib")
        ml.STATS_PATH = os.path.join(tempfile.gettempdir(), "missing_ctd_stats.json")
        ml._try_load()
        self.assertIsNone(ml._model)
        self.assertIsNone(ml._stats)

    def test_missing_stats_artifact_does_not_crash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "valid-model.joblib")
            missing_stats_path = os.path.join(temp_dir, "missing-stats.json")

            fitted_model = IsolationForest(
                n_estimators=20,
                contamination=0.03,
                random_state=42,
            )
            training_rows = np.array([
                [1.0, 100.0, 0.1, 0.0] + [0.0] * 12,
                [2.0, 200.0, 0.2, 0.0] + [0.0] * 12,
                [3.0, 300.0, 0.3, 0.0] + [0.0] * 12,
            ])
            fitted_model.fit(training_rows)
            joblib.dump(fitted_model, model_path)

            ml.MODEL_PATH = model_path
            ml.STATS_PATH = missing_stats_path
            ml._try_load()
            self.assertIsNone(ml._model)
            self.assertIsNone(ml._stats)
            self.assertFalse(os.path.exists(missing_stats_path))

    def test_corrupted_model_fails_gracefully(self):
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as model_file:
            model_path = model_file.name
            model_file.write(b"not-a-joblib-model")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as stats_file:
            stats_path = stats_file.name
            json.dump({name: {"mean": 0.0, "std": 1.0} for name in FEATURE_NAMES}, stats_file)
        try:
            ml.MODEL_PATH = model_path
            ml.STATS_PATH = stats_path
            ml._try_load()
            self.assertIsNone(ml._model)
            self.assertIsNone(ml._stats)
        finally:
            os.unlink(model_path)
            os.unlink(stats_path)

    def test_rule_detectors_work_when_ml_unavailable(self):
        ml._model = None
        ml._stats = None
        ml._load_attempted = False
        ml._warned_missing = False
        ml.MODEL_PATH = os.path.join(tempfile.gettempdir(), "missing_ctd_model.joblib")
        ml.STATS_PATH = os.path.join(tempfile.gettempdir(), "missing_ctd_stats.json")
        engine = DetectorEngine(use_ml=True)
        results = engine.analyze({
            "unique_destination_ports": 10,
            "active_flows": 11,
            "syn_packet_ratio": 0.85,
            "flows_per_second": 11.0,
        })
        self.assertIsNone(ml._model)
        self.assertIsNone(ml._stats)
        self.assertTrue(any(result.detected for result in results))


if __name__ == "__main__":
    unittest.main()
