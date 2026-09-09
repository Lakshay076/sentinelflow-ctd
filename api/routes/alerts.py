import time
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from alerts.alert_store import AlertStore


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"],
)

store = AlertStore()


SIMULATION_PRESETS = {
    "PORT_SCAN": {
        "source_ip": "192.168.1.105",
        "attack_type": "PORT_SCAN",
        "severity": "HIGH",
        "confidence": 0.92,
        "reasons": [
            "High unique destination port count: 42 (threshold 10)",
            "Flow fanout rate: 45.2 flows/sec",
            "SYN packet ratio: 0.94",
        ],
    },
    "SYN_FLOOD": {
        "source_ip": "10.0.0.88",
        "attack_type": "SYN_FLOOD",
        "severity": "HIGH",
        "confidence": 0.98,
        "reasons": [
            "SYN packet rate: 350.0 packets/sec (threshold 50.0)",
            "Incomplete handshake ratio: 0.96",
            "Lack of incoming ACK confirmations",
        ],
    },
    "DATA_EXFILTRATION": {
        "source_ip": "192.168.1.201",
        "attack_type": "DATA_EXFILTRATION",
        "severity": "HIGH",
        "confidence": 0.88,
        "reasons": [
            "Asymmetric outbound/inbound byte ratio: 18.4 (threshold 5.0)",
            "Outbound volume: 15.2 MB in window",
            "Anomalous persistent egress flow",
        ],
    },
    "C2_BEACONING": {
        "source_ip": "172.16.0.45",
        "attack_type": "C2_BEACONING",
        "severity": "MEDIUM",
        "confidence": 0.85,
        "reasons": [
            "Regular inter-arrival timing: CoV 0.08 (threshold < 0.20)",
            "Periodic check-in interval: 10.02 seconds across 8 connections",
            "Destination: 198.51.100.24:443",
        ],
    },
    "DGA_DNS_TUNNELLING": {
        "source_ip": "192.168.1.144",
        "attack_type": "DGA_DNS_TUNNELLING",
        "severity": "HIGH",
        "confidence": 0.91,
        "reasons": [
            "High Shannon entropy in queried domains: 4.35 bits (threshold 3.80)",
            "Excessive query name length: 58 characters",
            "Rapid NXDOMAIN sequence for randomly generated subdomains",
        ],
    },
    "TLS_METADATA_ANOMALY": {
        "source_ip": "192.168.1.189",
        "attack_type": "TLS_METADATA_ANOMALY",
        "severity": "MEDIUM",
        "confidence": 0.80,
        "reasons": [
            "Missing Server Name Indication (SNI) in ClientHello",
            "Unusual cipher suite count: 2 (expected >= 10 for standard browsers)",
            "JA3 fingerprint: 6734f37d979b75f8507858bf4e8972b4",
        ],
    },
    "ML_ANOMALY": {
        "source_ip": "192.168.1.77",
        "attack_type": "ML_ANOMALY",
        "severity": "HIGH",
        "confidence": 0.89,
        "reasons": [
            "Isolation Forest anomaly score: -0.245 (unsupervised outlier)",
            "Z-score deviation: flows_per_second (+3.8σ)",
            "Z-score deviation: syn_packet_ratio (+3.1σ)",
            "Multi-dimensional behavioral deviation across 16 features",
        ],
    },
}


class SimulateRequest(BaseModel):
    attack_type: str
    source_ip: Optional[str] = None


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
    if attack_key not in SIMULATION_PRESETS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown attack type '{attack_type}'. Available: {list(SIMULATION_PRESETS.keys())}",
        )

    preset = SIMULATION_PRESETS[attack_key]
    now = time.time()
    src = source_ip or preset["source_ip"]

    existing = store.find_active(source_ip=src, attack_type=preset["attack_type"])
    if existing:
        record = store.update(
            alert_id=existing.alert_id,
            timestamp=now,
            severity=preset["severity"],
            confidence=preset["confidence"],
            event_count=existing.event_count + 1,
            reasons=preset["reasons"],
        )
    else:
        record = store.create(
            source_ip=src,
            attack_type=preset["attack_type"],
            severity=preset["severity"],
            confidence=preset["confidence"],
            timestamp=now,
            reasons=preset["reasons"],
        )

    return {
        "status": "simulated",
        "alert": record.to_dict() if record else None,
    }


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
