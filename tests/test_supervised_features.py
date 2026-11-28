"""
SentinelFlow-CTD — Tests: Supervised Flow Feature Parity & Compatibility
========================================================================

Verifies Phase 2 acceptance criteria:
1. Feature vector shape is exactly 77 features in identical order to feature_names.json.
2. Feature definitions and units: Flow duration in microseconds, IATs in microseconds,
   packet length moments, flag counts.
3. Bidirectional packet handling: forward vs backward attribution relative to flow initiator.
4. Preprocessing parity: vectors can be transformed by preprocessor.joblib without error or NaN.
5. Model inference parity: vectors can be fed into the trained model to produce valid predictions.
6. Window-to-flow candidate selection: source IP correctly maps to active flows.
"""

import json
import os
import sys
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supervised.feature_extractor import (
    FEATURE_SCHEMA_VERSION,
    FLOW_FEATURE_NAMES,
    FlowFeatureAccumulator,
    LiveFlowTracker,
)
from supervised.train import load_artifacts
from supervised.predict import classify_features


ARTIFACTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "supervised",
    "artifacts",
)


@pytest.fixture
def trained_artifacts():
    """Load latest trained model artifacts."""
    return load_artifacts(ARTIFACTS_DIR, version="latest")


class TestFeatureSchemaParity:

    def test_schema_feature_count(self):
        """Must have exactly 77 features."""
        assert len(FLOW_FEATURE_NAMES) == 77
        assert FEATURE_SCHEMA_VERSION == "2.0"

    def test_schema_matches_saved_feature_names_json(self, trained_artifacts):
        """Feature names and order must match feature_names.json from training exactly."""
        expected_features = trained_artifacts["feature_names"]
        assert len(expected_features) == 77
        assert FLOW_FEATURE_NAMES == expected_features

    def test_extracted_vector_shape_and_dtype(self):
        """to_vector() must produce a 1D float32 array of shape (77,)."""
        acc = FlowFeatureAccumulator(
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=44332,
            dst_port=80,
            protocol="TCP",
        )
        acc.add_packet(timestamp=100.0, packet_length=60, src_ip="192.168.1.10", tcp_flags="S")
        acc.add_packet(timestamp=100.05, packet_length=60, src_ip="10.0.0.1", tcp_flags="SA")
        acc.add_packet(timestamp=100.10, packet_length=1500, src_ip="192.168.1.10", tcp_flags="A", payload_length=1440)

        vec = acc.to_vector()
        assert isinstance(vec, np.ndarray)
        assert vec.shape == (77,)
        assert vec.dtype == np.float32
        assert not np.isnan(vec).any()
        assert not np.isinf(vec).any()


class TestFeatureDefinitionsAndUnits:

    def test_flow_duration_in_microseconds(self):
        """Flow duration must be in microseconds (1e6 * seconds)."""
        acc = FlowFeatureAccumulator(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=5000,
            dst_port=80,
            protocol="TCP",
        )
        # 0.5 seconds between first and last packet = 500,000 microseconds
        acc.add_packet(timestamp=1.0, packet_length=100, src_ip="10.0.0.1")
        acc.add_packet(timestamp=1.5, packet_length=100, src_ip="10.0.0.2")

        feats = acc.extract_features()
        assert pytest.approx(feats["Flow Duration"], rel=1e-3) == 500_000.0

    def test_single_packet_flow_duration_is_zero(self):
        """A single-packet flow has 0 duration and safe rate calculations."""
        acc = FlowFeatureAccumulator(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=5000,
            dst_port=80,
            protocol="UDP",
        )
        acc.add_packet(timestamp=10.0, packet_length=128, src_ip="10.0.0.1")

        feats = acc.extract_features()
        assert feats["Flow Duration"] == 0.0
        assert feats["Total Fwd Packets"] == 1.0
        assert feats["Total Backward Packets"] == 0.0
        assert not np.isnan(feats["Flow Bytes/s"])
        assert not np.isinf(feats["Flow Bytes/s"])

    def test_inter_arrival_times_in_microseconds(self):
        """IATs must be in microseconds."""
        acc = FlowFeatureAccumulator(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=5000,
            dst_port=80,
            protocol="TCP",
        )
        # Packets at t=1.0, 1.02, 1.05
        # Inter-arrivals: 0.02s (20,000 us), 0.03s (30,000 us)
        acc.add_packet(timestamp=1.00, packet_length=100, src_ip="10.0.0.1")
        acc.add_packet(timestamp=1.02, packet_length=100, src_ip="10.0.0.1")
        acc.add_packet(timestamp=1.05, packet_length=100, src_ip="10.0.0.1")

        feats = acc.extract_features()
        assert pytest.approx(feats["Flow IAT Min"], rel=1e-2) == 20_000.0
        assert pytest.approx(feats["Flow IAT Max"], rel=1e-2) == 30_000.0
        assert pytest.approx(feats["Flow IAT Mean"], rel=1e-2) == 25_000.0

    def test_bidirectional_packet_and_byte_counts(self):
        """Forward and backward traffic are accurately separated based on initiator."""
        acc = FlowFeatureAccumulator(
            src_ip="192.168.1.5",
            dst_ip="8.8.8.8",
            src_port=53535,
            dst_port=53,
            protocol="UDP",
            initiator_ip="192.168.1.5",
        )
        # 3 queries from initiator (192.168.1.5) of 50 bytes
        acc.add_packet(timestamp=1.0, packet_length=50, src_ip="192.168.1.5")
        acc.add_packet(timestamp=1.1, packet_length=50, src_ip="192.168.1.5")
        acc.add_packet(timestamp=1.2, packet_length=50, src_ip="192.168.1.5")

        # 2 responses from server (8.8.8.8) of 150 bytes
        acc.add_packet(timestamp=1.05, packet_length=150, src_ip="8.8.8.8")
        acc.add_packet(timestamp=1.15, packet_length=150, src_ip="8.8.8.8")

        feats = acc.extract_features()
        assert feats["Total Fwd Packets"] == 3.0
        assert feats["Total Backward Packets"] == 2.0
        assert feats["Total Length of Fwd Packets"] == 150.0
        assert feats["Total Length of Bwd Packets"] == 300.0
        assert pytest.approx(feats["Down/Up Ratio"], rel=1e-3) == 2.0 / 3.0

    def test_tcp_flag_counts(self):
        """Flags (SYN, ACK, FIN, RST, PSH, URG) are parsed and counted."""
        acc = FlowFeatureAccumulator(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            src_port=4444,
            dst_port=80,
            protocol="TCP",
        )
        acc.add_packet(timestamp=1.0, packet_length=60, src_ip="10.0.0.5", tcp_flags="S")
        acc.add_packet(timestamp=1.1, packet_length=60, src_ip="10.0.0.10", tcp_flags="SA")
        acc.add_packet(timestamp=1.2, packet_length=200, src_ip="10.0.0.5", tcp_flags="PA")
        acc.add_packet(timestamp=1.3, packet_length=60, src_ip="10.0.0.10", tcp_flags="FA")
        acc.add_packet(timestamp=1.4, packet_length=60, src_ip="10.0.0.5", tcp_flags="R")

        feats = acc.extract_features()
        assert feats["SYN Flag Count"] == 2.0  # S, SA
        assert feats["ACK Flag Count"] == 3.0  # SA, PA, FA
        assert feats["PSH Flag Count"] == 1.0  # PA
        assert feats["FIN Flag Count"] == 1.0  # FA
        assert feats["RST Flag Count"] == 1.0  # R
        assert feats["Destination Port"] == 80.0


class TestLiveFlowTrackerAndWindowInteraction:

    def test_live_flow_tracker_accumulates_packets(self):
        """Tracker creates flow accumulators and groups packets into flows."""
        tracker = LiveFlowTracker(timeout_seconds=60.0)

        tracker.process_packet(
            timestamp=1.0,
            src_ip="10.0.0.50",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            packet_length=60,
            tcp_flags="S",
        )
        tracker.process_packet(
            timestamp=1.1,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.50",
            src_port=80,
            dst_port=12345,
            protocol="TCP",
            packet_length=60,
            tcp_flags="SA",
        )

        assert len(tracker.flows) == 1
        flow = list(tracker.flows.values())[0]
        assert len(flow.all_timestamps) == 2

    def test_candidate_flows_retrieval_for_anomalous_source(self):
        """When source 10.0.0.50 is anomalous, candidate flows are extracted."""
        tracker = LiveFlowTracker(timeout_seconds=60.0)

        # Flow 1: 10.0.0.50 -> 10.0.0.1:80
        tracker.process_packet(1.0, "10.0.0.50", "10.0.0.1", 10001, 80, "TCP", 60, "S")
        # Flow 2: 10.0.0.50 -> 10.0.0.1:443
        tracker.process_packet(1.1, "10.0.0.50", "10.0.0.1", 10002, 443, "TCP", 60, "S")
        # Flow 3: Unrelated flow 192.168.1.100 -> 8.8.8.8:53
        tracker.process_packet(1.2, "192.168.1.100", "8.8.8.8", 53000, 53, "UDP", 80)

        candidates = tracker.get_candidate_flows_for_source("10.0.0.50")
        assert len(candidates) == 2

        vectors = tracker.get_flow_vectors_for_source("10.0.0.50")
        assert len(vectors) == 2
        assert all(v.shape == (77,) for v in vectors)

    def test_flow_expiration(self):
        """Expired flows are removed after timeout."""
        tracker = LiveFlowTracker(timeout_seconds=5.0)
        tracker.process_packet(1.0, "10.0.0.5", "10.0.0.1", 5000, 80, "TCP", 60)
        assert len(tracker.flows) == 1

        tracker.remove_expired(current_time=10.0)  # 9 seconds elapsed > 5.0
        assert len(tracker.flows) == 0


class TestModelInferenceParity:

    def test_live_feature_vector_accepted_by_trained_pipeline(self, trained_artifacts):
        """
        Extracted vector must pass through preprocessor.joblib without raising any errors,
        and output must be 2D float with exactly 77 columns.
        """
        acc = FlowFeatureAccumulator("10.0.0.50", "10.0.0.1", 44000, 80, "TCP")
        for i in range(10):
            acc.add_packet(
                timestamp=10.0 + i * 0.05,
                packet_length=100 + i * 20,
                src_ip="10.0.0.50",
                tcp_flags="PA",
                payload_length=80 + i * 20,
            )

        raw_vec = acc.to_vector()
        preprocessor = trained_artifacts["preprocessor"]

        # Reshape to 2D
        X_in = raw_vec.reshape(1, -1)
        X_transformed = preprocessor.transform(X_in)

        assert X_transformed.shape == (1, 77)
        assert not np.isnan(X_transformed).any()
        assert not np.isinf(X_transformed).any()

    def test_live_feature_vector_predicts_valid_threat_category(self, trained_artifacts):
        """
        classify_features must run cleanly on the extracted vector and produce a structured result.
        """
        model = trained_artifacts["model"]
        preprocessor = trained_artifacts["preprocessor"]
        label_encoder = trained_artifacts["label_encoder"]

        # Simulate a burst resembling port scan / reconnaissance (SYN burst on port 80)
        acc = FlowFeatureAccumulator("10.0.0.50", "10.0.0.1", 44000, 80, "TCP")
        for i in range(5):
            acc.add_packet(
                timestamp=10.0 + i * 0.01,
                packet_length=40,
                src_ip="10.0.0.50",
                tcp_flags="S",
                header_length=40,
                payload_length=0,
            )

        raw_vec = acc.to_vector()

        results = classify_features(
            model=model,
            preprocessor=preprocessor,
            label_encoder=label_encoder,
            X=raw_vec,
            threshold=0.50,
        )

        assert len(results) == 1
        res = results[0]

        assert "predicted_threat" in res
        assert "confidence" in res
        assert "classification_status" in res
        assert "alternative_predictions" in res
        assert 0.0 <= res["confidence"] <= 1.0

        # Valid threat categories
        valid_categories = set(label_encoder.classes_) | {"UNCLASSIFIED"}
        assert res["predicted_threat"] in valid_categories
