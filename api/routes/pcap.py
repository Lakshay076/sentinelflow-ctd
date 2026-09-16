import glob
import os
import subprocess
import sys
import threading
import time
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from collector.pcap_replay_collector import replay
from scripts.validate_detections import validate

router = APIRouter(
    prefix="/api/pcap",
    tags=["PCAP Replay & Benchmarking"],
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

latest_benchmark_result = {
    "status": "idle",
    "pcap_file": "demo.pcap",
    "packet_count": 0,
    "byte_count": 0,
    "wall_elapsed": 0.0,
    "sustained_pps": 0.0,
    "sustained_mbps": 0.0,
    "flows_seen": 0,
    "flow_rate": 0.0,
    "last_run": None,
}


class GeneratePcapRequest(BaseModel):
    out: str = "demo.pcap"
    attacks: Optional[List[str]] = ["scan", "syn_flood", "exfil", "beacon", "dga", "tls"]


class ReplayPcapRequest(BaseModel):
    pcap_file: str = "demo.pcap"
    speed: float = 1.0
    max_speed: bool = True


@router.get("/files")
def get_pcap_files():
    """Lists available PCAP files and their ground-truth manifests."""
    pcap_files = []
    for pattern in ["*.pcap", "*.pcapng", "data/*.pcap"]:
        for full_path in glob.glob(os.path.join(PROJECT_ROOT, pattern)):
            rel_name = os.path.relpath(full_path, PROJECT_ROOT)
            stat = os.stat(full_path)
            gt_file = full_path + ".ground_truth.json"
            pcap_files.append({
                "filename": rel_name,
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "modified_at": stat.st_mtime,
                "has_ground_truth": os.path.exists(gt_file),
                "ground_truth_file": os.path.relpath(gt_file, PROJECT_ROOT) if os.path.exists(gt_file) else None,
            })
    return {"files": pcap_files}


@router.post("/generate")
def generate_synthetic_pcap(req: GeneratePcapRequest):
    """Generates a synthetic multi-host gateway traffic capture with ground-truth labels."""
    from scripts.generate_synthetic_traffic import (
        INTERNAL_HOSTS,
        EXTERNAL_HOSTS,
        build_normal_traffic,
        build_port_scan,
        build_syn_flood,
        build_exfiltration,
        build_c2_beaconing,
        build_dga_dns_tunnelling,
        build_tls_metadata_anomaly,
    )
    from scapy.all import wrpcap
    import json

    out_path = os.path.join(PROJECT_ROOT, req.out)
    packets = []
    ts = time.time()
    ts = build_normal_traffic(packets, ts, duration_s=30)

    builders = {
        "scan": build_port_scan,
        "syn_flood": build_syn_flood,
        "exfil": build_exfiltration,
        "beacon": build_c2_beaconing,
        "dga": build_dga_dns_tunnelling,
        "tls": build_tls_metadata_anomaly,
    }

    for name in req.attacks:
        if name in builders:
            ts = builders[name](packets, ts + 1.0)

    packets.sort(key=lambda p: p.time)
    wrpcap(out_path, packets)

    attacker_ip_by_attack = {
        "scan": ("10.0.0.50", "PORT_SCAN"),
        "syn_flood": ("10.0.0.51", "SYN_FLOOD"),
        "exfil": ("10.0.0.52", "DATA_EXFILTRATION"),
        "beacon": ("10.0.0.53", "C2_BEACONING"),
        "dga": ("10.0.0.54", "DGA_DNS_TUNNELLING"),
        "tls": ("10.0.0.55", "TLS_METADATA_ANOMALY"),
    }
    ground_truth = {
        "pcap_file": req.out,
        "expected_detections": [
            {"source_ip": ip, "attack_type": attack_type}
            for name, (ip, attack_type) in attacker_ip_by_attack.items()
            if name in req.attacks
        ],
        "benign_ips": INTERNAL_HOSTS,
    }
    gt_path = out_path + ".ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump(ground_truth, f, indent=2)

    return {
        "status": "success",
        "pcap_file": req.out,
        "ground_truth_file": req.out + ".ground_truth.json",
        "packet_count": len(packets),
        "internal_hosts": len(INTERNAL_HOSTS),
        "external_hosts": len(EXTERNAL_HOSTS),
        "attacks_included": req.attacks,
    }


@router.post("/replay")
def replay_pcap_file(req: ReplayPcapRequest):
    """Replays a PCAP file through the detection engine and returns real-time benchmark metrics."""
    global latest_benchmark_result

    target_path = os.path.join(PROJECT_ROOT, req.pcap_file)
    if not os.path.exists(target_path):
        raise HTTPException(
            status_code=404,
            detail=f"PCAP file '{req.pcap_file}' not found. Generate one first with /api/pcap/generate.",
        )

    try:
        benchmark = replay(
            pcap_path=target_path,
            speed=req.speed,
            max_speed=req.max_speed,
        )

        latest_benchmark_result = {
            "status": "completed",
            "pcap_file": req.pcap_file,
            "packet_count": benchmark.get("packet_count", 0),
            "byte_count": benchmark.get("byte_count", 0),
            "wall_elapsed": benchmark.get("wall_elapsed", 0.0),
            "sustained_pps": benchmark.get("sustained_pps", 0.0),
            "sustained_mbps": benchmark.get("sustained_mbps", 0.0),
            "flows_seen": benchmark.get("flows_seen", 0),
            "flow_rate": benchmark.get("flow_rate", 0.0),
            "windows_evaluated": benchmark.get("windows_evaluated", 0),
            "alert_events": benchmark.get("alert_events", 0),
            "last_run": time.time(),
        }

        return {
            "status": "success",
            "benchmark": latest_benchmark_result,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Replay error: {str(e)}")


@router.get("/benchmark")
def get_benchmark_status():
    """Returns the latest throughput benchmark and system measurement metrics."""
    return latest_benchmark_result


@router.get("/validate")
def validate_against_ground_truth(manifest: str = "demo.pcap.ground_truth.json"):
    """Evaluates detection accuracy (Precision, Recall, F1) against ground truth."""
    manifest_path = os.path.join(PROJECT_ROOT, manifest)
    if not os.path.exists(manifest_path):
        raise HTTPException(
            status_code=404,
            detail=f"Ground truth manifest '{manifest}' not found.",
        )

    try:
        report = validate(manifest_path)
        return {
            "status": "success",
            "report": report,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")
