"""
Phase 4 API Integration Tests — Supervised Classification Endpoints & Serialization
====================================================================================
"""

import pytest

import alerts.alert_store as alert_store_module
import api.main as api_main_module
import api.routes.alerts as alerts_route_module
from alerts.alert_manager import AlertManager
from api.main import get_stats
from api.routes.alerts import (
    get_active_alerts,
    get_alert,
    get_alert_history,
    get_classifier_status,
)
from detectors.detection_result import DetectionResult
from supervised.classifier import ThreatClassifier
from supervised.feature_extractor import LiveFlowTracker


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_api_ctd.db")
    monkeypatch.setattr(alert_store_module, "DB_FILE", db_file)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    test_store = alert_store_module.AlertStore()
    monkeypatch.setattr(alerts_route_module, "store", test_store)
    return test_store


def _create_classified_alert(manager: AlertManager, src_ip: str = "10.20.30.40"):
    tracker = LiveFlowTracker(timeout_seconds=60.0)
    for p in range(10):
        tracker.process_packet(
            timestamp=2000.0 + p * 0.01,
            src_ip=src_ip,
            dst_ip="10.20.30.1",
            src_port=50000 + p,
            dst_port=80 + p,
            protocol="TCP",
            packet_length=64,
            tcp_flags="S",
        )
    flows = tracker.get_candidate_flows_for_source(src_ip)
    det = DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity="HIGH",
        score=0.9,
        confidence=0.9,
        reasons=["Isolation Forest anomaly"],
    )
    return manager.process(
        source_ip=src_ip,
        detections=[det],
        timestamp=2000.5,
        candidate_flows=flows,
    )[0]


def test_classifier_status_endpoint(isolated_store):
    data = get_classifier_status()
    assert data["available"] is True
    assert data["model_version"] is not None
    assert data["feature_schema_version"] is not None
    assert "DOS_DDOS" in data["categories"]
    assert "UNCLASSIFIED" in data["categories"]
    assert isinstance(data["evaluation_metrics"], dict)


def test_alerts_and_stats_include_supervised_fields(isolated_store):
    manager = AlertManager(resolve_after=300.0, classifier=ThreatClassifier())
    manager.store = isolated_store

    alert = _create_classified_alert(manager)

    # 1. /api/alerts/active
    active_data = get_active_alerts()
    assert active_data["count"] == 1
    item = active_data["alerts"][0]
    assert item["alert_id"] == alert.alert_id
    assert item["predicted_threat"] == alert.predicted_threat
    assert item["classification_status"] == alert.classification_status
    assert item["model_version"] == alert.model_version

    # 2. Filter by predicted_threat
    filtered = get_active_alerts(predicted_threat=alert.predicted_threat)
    assert filtered["count"] == 1

    empty_filtered = get_active_alerts(predicted_threat="NON_EXISTENT_CLASS")
    assert empty_filtered["count"] == 0

    # 3. /api/alerts/history
    hist_data = get_alert_history(predicted_threat=alert.predicted_threat)
    assert hist_data["count"] == 1

    # 4. /api/alerts/{alert_id}
    detail = get_alert(alert.alert_id)
    assert detail["predicted_threat"] == alert.predicted_threat

    # 5. /api/stats
    stats = get_stats()
    assert stats["total_alerts"] == 1
    assert stats["active_alerts"] == 1
    assert stats["classifier_available"] is True
    assert alert.predicted_threat in stats["predicted_threats"]
