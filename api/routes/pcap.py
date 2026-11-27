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


from scripts.generate_synthetic_traffic import DEFAULT_ATTACKS


class GeneratePcapRequest(BaseModel):
    out: str = "demo.pcap"
    attacks: Optional[List[str]] = list(DEFAULT_ATTACKS)


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
        EXTERNAL_HOSTS,
        INTERNAL_HOSTS,
        generate_synthetic_pcap_file,
    )

    out_path = os.path.join(PROJECT_ROOT, req.out)
    result = generate_synthetic_pcap_file(
        out_path,
        attacks=req.attacks,
        pcap_label=req.out,
    )

    return {
        "status": "success",
        "pcap_file": req.out,
        "ground_truth_file": req.out + ".ground_truth.json",
        "packet_count": result["packet_count"],
        "internal_hosts": len(INTERNAL_HOSTS),
        "external_hosts": len(EXTERNAL_HOSTS),
        "attacks_included": result["attacks_included"],
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
            "alert_ids": benchmark.get("alert_ids", []),
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
        explicit_ids = None
        if (
            latest_benchmark_result.get("status") == "completed"
            and os.path.basename(latest_benchmark_result.get("pcap_file", ""))
            == os.path.basename(manifest_path.replace(".ground_truth.json", ""))
            and "alert_ids" in latest_benchmark_result
        ):
            explicit_ids = latest_benchmark_result["alert_ids"]

        report = validate(manifest_path, alert_ids=explicit_ids)
        return {
            "status": "success",
            "report": report,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")
