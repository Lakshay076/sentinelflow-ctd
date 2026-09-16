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
def get_active_alerts():
    alerts = store.active()

    return {
        "count": len(alerts),
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ],
    }


@router.get("/history")
def get_alert_history():
    alerts = store.all()

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


@router.get("/{alert_id}")
def get_alert(alert_id: int):
    alert = store.get(alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return alert.to_dict()
