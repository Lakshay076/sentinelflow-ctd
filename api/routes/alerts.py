import time
from typing import Optional
from demo.simulator import run_demo_simulation
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from alerts.alert_store import AlertStore


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"],
)

store = AlertStore()
DEMO_LAB_CONFIG = {
    "mode": "CONTROLLED_SIMULATION",
    "source_ip": "10.10.10.10",
    "target_ip": "10.10.10.20",
    "sensor_interface": "enp0s8",
    "sensor_mode": "PASSIVE",
}

class SimulateRequest(BaseModel):
    attack_type: str
    source_ip: Optional[str] = None

@router.get("/demo-config")
def get_demo_config():
    return DEMO_LAB_CONFIG

@router.get("/active")
def get_active_alerts(predicted_threat: Optional[str] = None):
    alerts = store.active()
    if predicted_threat:
        target = predicted_threat.upper()
        alerts = [a for a in alerts if (a.predicted_threat or "").upper() == target]

    return {
        "count": len(alerts),
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ],
    }


@router.get("/history")
def get_alert_history(predicted_threat: Optional[str] = None):
    alerts = store.all()
    if predicted_threat:
        target = predicted_threat.upper()
        alerts = [a for a in alerts if (a.predicted_threat or "").upper() == target]

    return {
        "count": len(alerts),
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ],
    }


@router.post("/simulate")
@router.post("/simulate/{attack_type}")
def simulate_attack(attack_type: str, source_ip: Optional[str] = None):
    attack_key = attack_type.upper()

    allowed_attacks = {
        "PORT_SCAN",
        "SYN_FLOOD",
        "UDP_FLOOD",
        "DISTRIBUTED_UDP_FLOOD",
        "C2_BEACONING",
        "DGA_DNS_TUNNELLING",
        "TLS_METADATA_ANOMALY",
        "DATA_EXFILTRATION",
    }

    if attack_key not in allowed_attacks:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown attack type '{attack_type}'. "
                f"Available: {sorted(allowed_attacks)}"
            ),
        )

    source = source_ip or DEMO_LAB_CONFIG["source_ip"]
    target = DEMO_LAB_CONFIG["target_ip"]

    try:
        result = run_demo_simulation(
            attack_type=attack_key,
            source_ip=source,
            target_ip=target,
        )

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Demo simulation failed: {exc}",
        )

@router.post("/resolve-all")
def resolve_all_alerts():
    now = time.time()
    active_alerts = store.active()
    resolved_count = 0
    for alert in active_alerts:
        res = store.resolve(alert.alert_id, timestamp=now)
        if res:
            resolved_count += 1

    return {
        "status": "success",
        "resolved_count": resolved_count,
    }


@router.post("/clear-history")
@router.delete("/history")
def clear_alert_history():
    cleared_count = store.clear_history()
    return {
        "status": "success",
        "cleared_count": cleared_count,
    }


@router.post("/clear-all")
@router.delete("/all")
def clear_all_alerts():
    cleared_count = store.clear_all()
    return {
        "status": "success",
        "cleared_count": cleared_count,
    }


@router.get("/classifier/status")
def get_classifier_status():
    """Return supervised classifier availability, version, and real evaluation summary."""
    from supervised.classifier import get_threat_classifier
    from supervised.feature_extractor import FEATURE_SCHEMA_VERSION
    from supervised.label_mapping import ORDERED_CATEGORIES, UNKNOWN_CATEGORY
    import json
    import os

    clf = get_threat_classifier()
    available = bool(clf and clf.is_available)
    manifest = {}
    eval_summary = {}

    if available and clf._artifacts:
        version_dir = os.path.join(clf.artifacts_dir, clf._artifacts["version"])
        manifest_path = os.path.join(version_dir, "manifest.json")
        eval_path = os.path.join(version_dir, "evaluation_report.json")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r") as f:
                    manifest = json.load(f)
            except Exception:
                pass
        if os.path.exists(eval_path):
            try:
                with open(eval_path, "r") as f:
                    report = json.load(f)
                    eval_summary = report.get("metrics", {})
            except Exception:
                pass

    return {
        "available": available,
        "model_version": clf._artifacts["version"] if (available and clf._artifacts) else None,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "confidence_threshold": clf.threshold if clf else None,
        "categories": list(ORDERED_CATEGORIES) + [UNKNOWN_CATEGORY],
        "manifest": manifest,
        "evaluation_metrics": eval_summary,
    }


@router.get("/{alert_id}")
def get_alert(alert_id: int):
    alert = store.get(alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return alert.to_dict()
