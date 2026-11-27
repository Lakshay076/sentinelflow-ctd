import json
import math
import time

import numpy as np
import pandas as pd
import pytest

from detectors.detection_result import DetectionResult
from detectors.detector_engine import DetectorEngine
from detectors.incident_correlator import IncidentCorrelator
from features.feature_context import FeatureContext
from inference import supervised_detector
from inference.supervised_schema import (
    SUPERVISED_CLASSES,
    SUPERVISED_DEFAULT_VALUES,
    SUPERVISED_FEATURE_NAMES,
    supervised_features_to_vector,
)
from inference.prepare_public_dataset import (
    _normalize_label_series,
    calibrate_confidence_threshold,
    deduplicate_feature_rows,
    feature_overlap_count,
    map_public_csv_frame,
    normalize_public_label,
    prepare_public_dataset,
    split_prepared_rows,
)
from inference import train_model_from_pcap
from inference.train_supervised import train_supervised


@pytest.fixture
def temporary_supervised_artifacts(monkeypatch, tmp_path):
    model_path = tmp_path / "supervised_model.joblib"
    metadata_path = tmp_path / "supervised_metadata.json"

    monkeypatch.setattr(supervised_detector, "MODEL_PATH", str(model_path))
    monkeypatch.setattr(supervised_detector, "METADATA_PATH", str(metadata_path))
    monkeypatch.setattr(supervised_detector, "_model", None)
    monkeypatch.setattr(supervised_detector, "_metadata", None)
    monkeypatch.setattr(supervised_detector, "_load_attempted", False)
    monkeypatch.setattr(supervised_detector, "_load_error", None)
    monkeypatch.setattr(supervised_detector, "_warned", set())

    return model_path, metadata_path


def _synthetic_seven_class_rows():
    rows = []
    for class_id, class_name in SUPERVISED_CLASSES.items():
        for sample_index in range(14):
            row = {
                name: float(SUPERVISED_DEFAULT_VALUES[name])
                for name in SUPERVISED_FEATURE_NAMES
            }
            row["packets_per_second"] = (
                class_id * 100.0 + sample_index + 1.0
            )
            row["bytes_per_second"] = (
                class_id * 1000.0 + sample_index * 10.0 + 1.0
            )
            row["syn_packet_ratio"] = class_id / 10.0
            row["unique_destinations"] = class_id * 10 + sample_index
            row["label"] = class_name
            rows.append(row)
    return rows


def test_supervised_schema_defaults_and_non_finite_values():
    features = {
        "packets_per_second": None,
        "bytes_per_second": math.nan,
        "syn_packet_ratio": math.inf,
    }

    vector = supervised_features_to_vector(features)

    assert len(vector) == 24
    assert all(isinstance(value, float) for value in vector)
    for index, name in enumerate(SUPERVISED_FEATURE_NAMES):
        if name not in features or features[name] is None:
            assert vector[index] == float(SUPERVISED_DEFAULT_VALUES[name])
        elif isinstance(features[name], float) and not math.isfinite(features[name]):
            assert vector[index] == float(SUPERVISED_DEFAULT_VALUES[name])


def test_missing_supervised_model_does_not_disrupt_detector_engine(
    temporary_supervised_artifacts,
):
    model_path, metadata_path = temporary_supervised_artifacts
    assert not model_path.exists()
    assert not metadata_path.exists()

    engine = DetectorEngine(use_ml=True, use_supervised_ml=True)
    rule_detectors = engine.source_detectors[:7]
    called_rules = []

    def track_rule(detector):
        def tracked(features):
            called_rules.append(detector.__name__)
            return detector(features)

        return tracked

    engine.source_detectors = [
        track_rule(detector)
        for detector in rule_detectors
    ] + engine.source_detectors[7:]

    context = FeatureContext(
        network={},
        sources={
            "192.0.2.10": {
                "packets": 20,
                "bytes": 2000,
                "packets_per_second": 20.0,
                "bytes_per_second": 2000.0,
                "tcp_packets": 20,
                "tcp_syn": 18,
                "tcp_ack": 0,
                "tcp_rst": 0,
                "syn_rate": 18.0,
                "rst_rate": 0.0,
                "syn_packet_ratio": 0.9,
                "rst_packet_ratio": 0.0,
                "unique_destinations": 1,
                "unique_destination_ports": 12,
                "active_flows": 12,
                "flows_per_second": 12.0,
                "ports_per_destination": 12.0,
                "outbound_inbound_ratio": 1.0,
                "bytes_received": 2000,
            }
        },
    )

    detections = engine.analyze_context(context)["192.0.2.10"]

    assert len(called_rules) == 7
    assert {result.attack_type for result in detections} >= {"PORT_SCAN"}


def test_seven_class_training_inference_and_latency(
    temporary_supervised_artifacts,
    tmp_path,
    capsys,
):
    model_path, metadata_path = temporary_supervised_artifacts
    rows = _synthetic_seven_class_rows()
    dataset_path = tmp_path / "synthetic_windows.csv"
    pd.DataFrame(rows).to_csv(dataset_path, index=False)

    train_supervised(
        dataset_path,
        model_path=model_path,
        metadata_path=metadata_path,
        random_state=23,
    )

    assert model_path.is_file()
    assert metadata_path.is_file()
    for class_id, class_name in SUPERVISED_CLASSES.items():
        sample = next(row for row in rows if row["label"] == class_name)
        features = {
            name: sample[name]
            for name in SUPERVISED_FEATURE_NAMES
        }
        result = supervised_detector.detect_supervised_threat(features)
        if class_id == 0:
            assert not result.detected
        else:
            assert result.detected
            assert result.attack_type == class_name

    latency_features = {
        name: rows[-1][name]
        for name in SUPERVISED_FEATURE_NAMES
    }
    supervised_detector.detect_supervised_threat(latency_features)
    start = time.perf_counter()
    for _ in range(100):
        supervised_detector.detect_supervised_threat(latency_features)
    average_latency_ms = (
        (time.perf_counter() - start) / 100
    ) * 1000.0
    with capsys.disabled():
        print(
            f"Supervised inference average: "
            f"{average_latency_ms:.3f} ms/window"
        )
    assert average_latency_ms < 50.0


def test_hybrid_correlator_preserves_all_three_detection_layers():
    rule = DetectionResult(
        detected=True,
        attack_type="PORT_SCAN",
        severity="HIGH",
        score=3,
        confidence=0.9,
        reasons=["Rule evidence: destination-port fan-out"],
    )
    supervised = DetectionResult(
        detected=True,
        attack_type="PORT_SCAN",
        severity="CRITICAL",
        score=97.0,
        confidence=0.97,
        reasons=[
            "[Supervised ML] Predicted PORT_SCAN with confidence 0.97",
            "[Supervised ML] Observed unique_destination_ports=12",
        ],
    )
    isolation_forest = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="MEDIUM",
        score=2,
        confidence=0.6,
        reasons=["Isolation Forest anomaly evidence"],
    )
    supervised_only = DetectionResult(
        detected=True,
        attack_type="C2_BEACONING",
        severity="HIGH",
        score=88.0,
        confidence=0.88,
        reasons=["[Supervised ML] Predicted C2_BEACONING with confidence 0.88"],
    )
    unexplained_anomaly = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="LOW",
        score=1,
        confidence=0.4,
        reasons=["Unexplained anomaly"],
    )

    correlated = IncidentCorrelator().correlate(
        {
            "192.0.2.10": [rule, supervised, isolation_forest],
            "192.0.2.20": [supervised_only],
            "192.0.2.30": [unexplained_anomaly],
        },
        communication_context={},
    )

    merged = correlated["192.0.2.10"]
    assert len(merged) == 1
    assert merged[0].attack_type == "PORT_SCAN"
    assert (merged[0].severity, merged[0].score, merged[0].confidence) == (
        "HIGH",
        3,
        0.9,
    )
    assert "Rule evidence: destination-port fan-out" in merged[0].reasons
    assert all(reason in merged[0].reasons for reason in supervised.reasons)
    assert any("ML corroboration" in reason for reason in merged[0].reasons)
    assert any(
        "Isolation Forest anomaly evidence" in reason
        for reason in merged[0].reasons
    )

    assert correlated["192.0.2.20"] == [supervised_only]
    assert correlated["192.0.2.30"] == [unexplained_anomaly]


def test_public_csv_flow_columns_map_to_supervised_features():
    frame = pd.DataFrame(
        {
            "Timestamp": ["2026-01-01 00:00:00", "2026-01-01 00:00:01"],
            "Source IP": ["192.0.2.1", "192.0.2.2"],
            "Destination IP": ["198.51.100.1", "198.51.100.2"],
            "Destination Port": [443, 53],
            "Flow Duration": [1_000_000, 2_000_000],
            "Total Fwd Packets": [10, 2],
            "Total Backward Packets": [5, 8],
            "Total Length of Fwd Packets": [1000, 200],
            "Bwd Packet Length Total": [500, 300],
            "SYN Flag Count": [3, 0],
            "RST Flag Count": [1, 1],
            "Flow Bytes/s": [1500.0, 250.0],
            "Fwd Packets/s": [10.0, 1.0],
            "Bwd Packets/s": [5.0, 4.0],
            "Label": ["DDoS", "PortScan"],
        }
    )

    mapped = map_public_csv_frame(frame, capture_id="flows.csv")

    assert mapped["label"].tolist() == [1, 2]
    assert mapped["capture_id"].unique().tolist() == ["flows.csv"]
    assert mapped.loc[0, "packets_per_second"] == 15.0
    assert mapped.loc[0, "bytes_per_second"] == 1500.0
    assert mapped.loc[0, "syn_packet_ratio"] == pytest.approx(0.2)
    assert mapped.loc[0, "unique_destination_ports"] == 1.0
    assert mapped.loc[0, "active_flows"] == 1.0
    assert mapped.loc[0, "bytes_received"] == 500.0
    assert mapped.loc[0, "outbound_inbound_ratio"] == 2.0
    assert mapped.loc[0, "exfil_bytes_per_second"] == 1000.0
    assert mapped.loc[0, "dns_high_entropy_ratio"] == float(
        SUPERVISED_DEFAULT_VALUES["dns_high_entropy_ratio"]
    )
    assert mapped.loc[0, "tls_avg_cipher_count"] == float(
        SUPERVISED_DEFAULT_VALUES["tls_avg_cipher_count"]
    )


def test_public_dataset_capture_split_has_no_feature_or_capture_overlap():
    rows = []
    for capture_index in range(6):
        for class_id, class_name in SUPERVISED_CLASSES.items():
            row = {
                name: float(SUPERVISED_DEFAULT_VALUES[name])
                for name in SUPERVISED_FEATURE_NAMES
            }
            row["packets_per_second"] = capture_index * 100.0 + class_id + 1.0
            row.update(
                capture_id=f"capture-{capture_index}.csv",
                source_ip="",
                window_timestamp=float(capture_index),
                label=class_id,
            )
            rows.append(row)

    splits = split_prepared_rows(
        pd.DataFrame(rows),
        strategy="capture",
        random_state=13,
    )
    capture_sets = {
        name: set(frame["capture_id"])
        for name, frame in splits.items()
    }

    assert capture_sets["train"].isdisjoint(capture_sets["validation"])
    assert capture_sets["train"].isdisjoint(capture_sets["test"])
    assert capture_sets["validation"].isdisjoint(capture_sets["test"])
    assert feature_overlap_count(splits["train"], splits["test"]) == 0
    assert all(not frame.empty for frame in splits.values())


def test_public_dataset_chronological_split_is_per_capture_and_label():
    rows = []
    for class_id in SUPERVISED_CLASSES:
        for sample_index in range(20):
            row = {
                name: float(SUPERVISED_DEFAULT_VALUES[name])
                for name in SUPERVISED_FEATURE_NAMES
            }
            row["packets_per_second"] = class_id * 100.0 + sample_index + 1.0
            row.update(
                capture_id="capture-a.pcap",
                source_ip="",
                window_timestamp=float(sample_index),
                label=class_id,
            )
            rows.append(row)

    splits = split_prepared_rows(
        pd.DataFrame(rows),
        strategy="chronological",
    )

    for class_id in SUPERVISED_CLASSES:
        train = splits["train"].loc[splits["train"]["label"] == class_id]
        validation = splits["validation"].loc[
            splits["validation"]["label"] == class_id
        ]
        test = splits["test"].loc[splits["test"]["label"] == class_id]
        assert (len(train), len(validation), len(test)) == (14, 3, 3)
        assert train["window_timestamp"].max() < validation[
            "window_timestamp"
        ].min()
        assert validation["window_timestamp"].max() < test[
            "window_timestamp"
        ].min()

    assert feature_overlap_count(splits["train"], splits["validation"]) == 0
    assert feature_overlap_count(splits["train"], splits["test"]) == 0
    assert feature_overlap_count(splits["validation"], splits["test"]) == 0


def test_public_dataset_threshold_calibration_enforces_benign_fpr_limit():
    y_true = np.array([0] * 100 + [class_id for class_id in range(1, 7) for _ in range(10)])
    probabilities = np.zeros((len(y_true), 7), dtype=float)
    probabilities[:100, 0] = 0.9
    probabilities[0, 2] = 0.72
    probabilities[0, 0] = 0.28
    for index, class_id in enumerate(y_true[100:], start=100):
        probabilities[index, class_id] = 0.8
        probabilities[index, 0] = 0.2

    calibration = calibrate_confidence_threshold(
        y_true,
        probabilities,
        classes=list(SUPERVISED_CLASSES),
    )

    assert calibration["confidence_threshold"] == 0.8
    assert calibration["benign_false_positive_rate"] <= 0.01
    assert calibration["macro_f1"] == 1.0


def test_public_dataset_calibration_saves_model_and_threshold_metadata(tmp_path):
    input_paths = []
    for capture_index in range(3):
        rows = []
        for class_id, class_name in SUPERVISED_CLASSES.items():
            for sample_index in range(14):
                row = {
                    name: float(SUPERVISED_DEFAULT_VALUES[name])
                    for name in SUPERVISED_FEATURE_NAMES
                }
                row["packets_per_second"] = (
                    class_id * 100.0 + sample_index + capture_index * 0.01
                )
                row["bytes_per_second"] = (
                    class_id * 1000.0 + sample_index * 10.0 + capture_index * 0.1
                )
                row["syn_packet_ratio"] = class_id / 10.0
                row["label"] = class_name
                rows.append(row)
        input_path = tmp_path / f"capture-{capture_index}.csv"
        pd.DataFrame(rows).to_csv(input_path, index=False)
        input_paths.append(input_path)

    model_path = tmp_path / "supervised_model.joblib"
    metadata_path = tmp_path / "supervised_metadata.json"
    result = prepare_public_dataset(
        mode="csv",
        input_paths=input_paths,
        output_dir=tmp_path / "prepared",
        random_state=7,
        calibrate_threshold=True,
        model_path=model_path,
        metadata_path=metadata_path,
    )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    assert model_path.is_file()
    assert metadata_path.is_file()
    assert metadata["confidence_threshold"] == result["calibration"][
        "confidence_threshold"
    ]
    assert metadata["threshold_calibration"][
        "benign_false_positive_rate"
    ] <= 0.01
    assert metadata["metrics"]["held_out_test"]["rows"] > 0
    assert metadata["metrics"]["held_out_test"]["feature_overlap_count"] == 0
    assert result["test_metrics"]["macro_f1"] >= 0.0
    assert all(value == 0 for value in result["overlap_counts"].values())


def test_unknown_public_labels_are_strict_by_default_and_optional_to_drop():
    labels = pd.Series(
        [
            "BENIGN",
            "Normal",
            "DDoS",
            "DoS",
            "DoS Hulk",
            "DoS GoldenEye",
            "DoS slowloris",
            "DoS Slowhttptest",
            "Heartbleed",
            "Web Attack",
        ]
    )

    with pytest.raises(ValueError, match="Unsupported public dataset label"):
        _normalize_label_series(labels)

    mapped, unknown = _normalize_label_series(
        labels,
        ignore_unknown_labels=True,
    )

    assert mapped.iloc[:2].tolist() == [0.0, 0.0]
    assert mapped.iloc[2:8].tolist() == [1.0] * 6
    assert mapped.iloc[8:].isna().all()
    assert unknown == {"Heartbleed": 1, "Web Attack": 1}
    assert normalize_public_label("DoS Slowhttptest") == 1


def test_ambiguous_feature_vectors_are_removed_before_splitting():
    rows = []
    for label, packet_rate in ((0, 10.0), (1, 10.0), (2, 20.0)):
        row = {
            name: float(SUPERVISED_DEFAULT_VALUES[name])
            for name in SUPERVISED_FEATURE_NAMES
        }
        row.update(
            packets_per_second=packet_rate,
            capture_id=f"capture-{label}",
            source_ip="",
            window_timestamp=float(label),
            label=label,
        )
        rows.append(row)

    deduplicated = deduplicate_feature_rows(pd.DataFrame(rows))

    assert deduplicated["label"].tolist() == [2]
    assert deduplicated["packets_per_second"].tolist() == [20.0]


@pytest.mark.parametrize("split_strategy", ["capture", "chronological"])
def test_supplement_pcap_windows_follow_split_strategy(
    tmp_path,
    monkeypatch,
    split_strategy,
):
    input_paths = []
    for capture_index in range(4):
        rows = []
        for class_id, class_name in SUPERVISED_CLASSES.items():
            for sample_index in range(2):
                row = {
                    name: float(SUPERVISED_DEFAULT_VALUES[name])
                    for name in SUPERVISED_FEATURE_NAMES
                }
                row["packets_per_second"] = (
                    capture_index * 1000.0 + class_id * 10.0 + sample_index + 1
                )
                row["bytes_per_second"] = (
                    capture_index * 10000.0
                    + class_id * 100.0
                    + sample_index
                    + 1
                )
                row.update(
                    window_timestamp=1_700_000_000 + capture_index * 100 + sample_index,
                    label=class_name,
                )
                rows.append(row)
        input_path = tmp_path / f"capture-{capture_index}.csv"
        pd.DataFrame(rows).to_csv(input_path, index=False)
        input_paths.append(input_path)

    pcap_path = tmp_path / "supplement.pcap"
    pcap_path.write_bytes(b"placeholder")
    ground_truth_path = tmp_path / "supplement.pcap.ground_truth.json"
    ground_truth_path.write_text(
        json.dumps(
            {
                "pcap_file": "supplement.pcap",
                "expected_detections": [
                    {
                        "source_ip": "198.51.100.10",
                        "attack_type": "DGA_DNS_TUNNELLING",
                    },
                    {
                        "source_ip": "198.51.100.12",
                        "attack_type": "TLS_METADATA_ANOMALY",
                    },
                ],
                "benign_ips": ["198.51.100.11"],
            }
        ),
        encoding="utf-8",
    )

    records = []
    for source_ip, packet_rate in (
        ("198.51.100.10", 50_001.0),
        ("198.51.100.11", 60_001.0),
        ("198.51.100.12", 70_001.0),
    ):
        for sample_index in range(20):
            features = {
                name: float(SUPERVISED_DEFAULT_VALUES[name])
                for name in SUPERVISED_FEATURE_NAMES
            }
            features["packets_per_second"] = packet_rate + sample_index
            features["bytes_per_second"] = packet_rate * 2 + sample_index
            timestamp = 1_700_001_000.0 + sample_index
            records.append(
                {
                    "source_ip": source_ip,
                    "window_timestamp": timestamp,
                    "window_start": timestamp - 0.5,
                    "features": features,
                }
            )

    def fake_extract_training_vectors(pcap_path, capture_records=None):
        capture_records.extend(records)

    monkeypatch.setattr(
        train_model_from_pcap,
        "extract_training_vectors",
        fake_extract_training_vectors,
    )
    result = prepare_public_dataset(
        mode="csv",
        input_paths=input_paths,
        output_dir=tmp_path / "prepared-supplements",
        random_state=19,
        split_strategy=split_strategy,
        supplement_pcap_paths=[pcap_path],
        supplement_ground_truth_paths=[ground_truth_path],
    )

    assert all(value == 0 for value in result["overlap_counts"].values())
    if split_strategy == "capture":
        assert result["supplement_rows_by_split"] == {
            "train": 60,
            "validation": 0,
            "test": 0,
        }
    else:
        assert result["supplement_rows_by_split"] == {
            "train": 42,
            "validation": 9,
            "test": 9,
        }
        assert result["supplement_rows_added_to_train"] == 42
        test_labels = set(result["splits"]["test"]["label"])
        assert 4 in test_labels
        assert 5 in test_labels
        for split_name in ("train", "validation", "test"):
            assert "supplement.pcap" in set(
                result["splits"][split_name]["capture_id"]
            )
