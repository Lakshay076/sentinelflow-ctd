"""
Phase 3 Integration Tests — Supervised Threat Classification in Alert Pipeline
==============================================================================

Verifies:
1. ML_ANOMALY detections with candidate flows are enriched with supervised
   threat category, confidence, alternative predictions, and supporting features.
2. Low-confidence predictions fall back to UNCLASSIFIED.
3. Missing candidate flows preserve the original alert with NO_CANDIDATE_FLOWS.
4. Missing or broken model artifacts NEVER suppress or crash alert generation.
5. Existing rule-based detections continue to work unchanged.
6. AlertStore persistence (create, update, get, active) preserves all Phase 3 fields.
"""

import os
import pytest
import alerts.alert_store as alert_store_module
from alerts.alert_manager import AlertManager
from detectors.detection_result import DetectionResult
from supervised.classifier import ThreatClassifier
from supervised.feature_extractor import LiveFlowTracker


@pytest.fixture
def temp_alert_manager(tmp_path, monkeypatch):
    """Create an AlertManager backed by an isolated temporary SQLite database."""
    db_file = str(tmp_path / "test_ctd_alerts.db")
    monkeypatch.setattr(alert_store_module, "DB_FILE", db_file)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return db_file


def _build_sample_flows(src_ip: str = "10.0.0.50") -> list:
    tracker = LiveFlowTracker(timeout_seconds=60.0)
    t = 1000.0
    for port in range(80, 90):
        tracker.process_packet(
            timestamp=t,
            src_ip=src_ip,
            dst_ip="10.0.0.10",
            src_port=40000 + port,
            dst_port=port,
            protocol="TCP",
            packet_length=60,
            tcp_flags="S",
            header_length=20,
            payload_length=0,
            window_size=1024,
        )
        t += 0.01
    return tracker.get_candidate_flows_for_source(src_ip)


def test_ml_anomaly_enriched_and_persisted(temp_alert_manager):
    """ML_ANOMALY with candidate flows is classified and persisted in AlertStore."""
    classifier = ThreatClassifier()
    assert classifier.is_available, "Trained Phase 1 model artifacts should be available"

    manager = AlertManager(resolve_after=300.0, classifier=classifier)
    flows = _build_sample_flows("10.0.0.50")

    detection = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="HIGH",
        score=0.92,
        confidence=0.88,
        reasons=["Isolation Forest anomaly score exceeded threshold"],
    )

    alerts = manager.process(
        source_ip="10.0.0.50",
        detections=[detection],
        timestamp=1000.5,
        candidate_flows=flows,
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.attack_type == "ML_ANOMALY"
    assert alert.predicted_threat is not None
    assert alert.threat_confidence is not None
    assert 0.0 <= alert.threat_confidence <= 1.0
    assert alert.classification_status in ("CLASSIFIED", "LOW_CONFIDENCE")
    assert alert.model_version is not None
    assert alert.feature_schema_version is not None

    # Verify persistence round-trip via AlertStore.get()
    fetched = manager.store.get(alert.alert_id)
    assert fetched is not None
    assert fetched.predicted_threat == alert.predicted_threat
    assert fetched.threat_confidence == pytest.approx(alert.threat_confidence)
    assert fetched.classification_status == alert.classification_status
    assert fetched.model_version == alert.model_version
    assert fetched.feature_schema_version == alert.feature_schema_version
    assert isinstance(fetched.alternative_predictions, list)


def test_low_confidence_falls_back_to_unclassified(temp_alert_manager):
    """Confidence below threshold yields UNCLASSIFIED and LOW_CONFIDENCE status."""
    # Impossibly high threshold forces fallback
    classifier = ThreatClassifier(threshold=0.999999)
    manager = AlertManager(resolve_after=300.0, classifier=classifier)
    flows = _build_sample_flows("10.0.0.51")

    detection = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="MEDIUM",
        score=0.75,
        confidence=0.75,
        reasons=["Anomaly detected"],
    )

    alerts = manager.process(
        source_ip="10.0.0.51",
        detections=[detection],
        timestamp=1001.0,
        candidate_flows=flows,
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.predicted_threat == "UNCLASSIFIED"
    assert alert.classification_status in ("LOW_CONFIDENCE", "UNCLASSIFIED")
    assert any("UNCLASSIFIED" in r for r in alert.reasons)


def test_no_candidate_flows_preserves_alert(temp_alert_manager):
    """ML_ANOMALY without candidate flows still creates an alert safely."""
    classifier = ThreatClassifier()
    manager = AlertManager(resolve_after=300.0, classifier=classifier)

    detection = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="MEDIUM",
        score=0.80,
        confidence=0.80,
        reasons=["Window anomaly"],
    )

    alerts = manager.process(
        source_ip="10.0.0.52",
        detections=[detection],
        timestamp=1002.0,
        candidate_flows=[],
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.attack_type == "ML_ANOMALY"
    assert alert.predicted_threat is None
    assert alert.classification_status == "NO_CANDIDATE_FLOWS"


def test_model_unavailable_never_suppresses_alert(temp_alert_manager, tmp_path):
    """Missing model artifacts must never suppress an existing alert."""
    missing_dir = str(tmp_path / "nonexistent_artifacts")
    classifier = ThreatClassifier(artifacts_dir=missing_dir)
    assert not classifier.is_available

    manager = AlertManager(resolve_after=300.0, classifier=classifier)
    flows = _build_sample_flows("10.0.0.53")

    detection = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="HIGH",
        score=0.95,
        confidence=0.95,
        reasons=["Isolation Forest anomaly"],
    )

    alerts = manager.process(
        source_ip="10.0.0.53",
        detections=[detection],
        timestamp=1003.0,
        candidate_flows=flows,
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.attack_type == "ML_ANOMALY"
    assert alert.classification_status == "MODEL_UNAVAILABLE"
    assert alert.predicted_threat is None


def test_inference_exception_never_suppresses_alert(temp_alert_manager):
    """Runtime exception in classifier must be caught and alert preserved."""
    class BrokenClassifier:
        is_available = True
        def classify_flows(self, flows):
            raise RuntimeError("Simulated inference crash")

    manager = AlertManager(resolve_after=300.0, classifier=BrokenClassifier())
    flows = _build_sample_flows("10.0.0.54")

    detection = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="HIGH",
        score=0.90,
        confidence=0.90,
        reasons=["Anomaly"],
    )

    alerts = manager.process(
        source_ip="10.0.0.54",
        detections=[detection],
        timestamp=1004.0,
        candidate_flows=flows,
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.attack_type == "ML_ANOMALY"
    assert alert.classification_status == "ERROR"


def test_rule_based_detector_unaffected(temp_alert_manager):
    """Rule-based detections without candidate flows work identically to before."""
    classifier = ThreatClassifier()
    manager = AlertManager(resolve_after=300.0, classifier=classifier)

    detection = DetectionResult(
        detected=True,
        attack_type="PORT_SCAN",
        severity="HIGH",
        score=1.0,
        confidence=0.99,
        reasons=["Scanned 25 unique ports in 1s"],
    )

    alerts = manager.process(
        source_ip="10.0.0.55",
        detections=[detection],
        timestamp=1005.0,
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.attack_type == "PORT_SCAN"
    assert alert.classification_status is None
    assert alert.predicted_threat is None


def test_alert_update_persists_classification(temp_alert_manager):
    """Updating an active alert enriches and persists classification fields."""
    classifier = ThreatClassifier()
    manager = AlertManager(resolve_after=300.0, classifier=classifier)

    # First event: no candidate flows
    d1 = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="MEDIUM",
        score=0.70,
        confidence=0.70,
        reasons=["Initial anomaly"],
    )
    a1 = manager.process(
        source_ip="10.0.0.56",
        detections=[d1],
        timestamp=1006.0,
        candidate_flows=[],
    )[0]
    assert a1.classification_status == "NO_CANDIDATE_FLOWS"

    # Second event: candidate flows arrive
    flows = _build_sample_flows("10.0.0.56")
    d2 = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="HIGH",
        score=0.91,
        confidence=0.91,
        reasons=["Continued anomaly"],
    )
    a2 = manager.process(
        source_ip="10.0.0.56",
        detections=[d2],
        timestamp=1007.0,
        candidate_flows=flows,
    )[0]

    assert a2.alert_id == a1.alert_id
    assert a2.event_count == 2
    assert a2.classification_status in ("CLASSIFIED", "LOW_CONFIDENCE")
    assert a2.predicted_threat is not None

    fetched = manager.store.get(a1.alert_id)
    assert fetched.event_count == 2
    assert fetched.predicted_threat == a2.predicted_threat
    assert fetched.classification_status == a2.classification_status
