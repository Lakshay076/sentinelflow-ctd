"""
CTD -- Detection Validator (proof that detection actually works)

Takes a ground-truth manifest (which source IPs SHOULD have been
flagged, and as what attack type) and compares it against what's
actually sitting in the alerts database after a replay run.

This is the "show me it works" script: run it right after a
pcap_replay_collector.py run and get a scored report you can put
straight into your SIH demo / documentation --

    True Positives   : attacks that were correctly caught
    False Negatives  : attacks that were MISSED (bad)
    False Positives  : benign IPs wrongly flagged (bad)
    Precision/Recall/F1 per threat class

Usage:
    # 1) clear old alerts so this run is a clean measurement
    python -c "from alerts.alert_store import AlertStore; AlertStore().clear_all()"

    # 2) generate + replay a labeled synthetic scenario
    python scripts/generate_synthetic_traffic.py --out demo.pcap
    python -m collector.pcap_replay_collector demo.pcap --max-speed

    # 3) score it
    python scripts/validate_detections.py demo.pcap.ground_truth.json
"""

import argparse
import json
import os
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.alert_store import AlertStore


def load_ground_truth(path: str):
    with open(path) as f:
        return json.load(f)


def _compute_pr_f1(tp: int, fp: int, fn: int):
    precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else float("nan")
    )
    return precision, recall, f1


def validate(
    ground_truth_path: str,
    alert_ids=None,
    use_latest_replay: bool = True,
):
    gt = load_ground_truth(ground_truth_path)
    expected = gt["expected_detections"]
    benign_ips = set(gt.get("benign_ips", []))
    pcap_file = gt.get("pcap_file")

    store = AlertStore()
    scope = "all_alerts"

    if alert_ids is not None:
        evaluated_alerts = store.get_many(alert_ids)
        scope = "explicit_alert_ids"
    elif use_latest_replay:
        latest_run = store.get_latest_replay_run(pcap_file=pcap_file)
        if latest_run is not None:
            evaluated_alerts = store.get_many(latest_run["alert_ids"])
            scope = f"latest_replay (run #{latest_run['run_id']})"
        else:
            evaluated_alerts = store.all()
    else:
        evaluated_alerts = store.all()

    # index actual alerts by (source_ip, attack_type) -> best confidence seen
    actual = {}
    for alert in evaluated_alerts:
        key = (alert.source_ip, alert.attack_type)
        actual[key] = max(actual.get(key, 0.0), alert.confidence)

    print("=" * 72)
    print("CTD -- DETECTION VALIDATION REPORT")
    print("=" * 72)
    print(f"Ground truth file : {ground_truth_path}")
    print(f"Validation scope  : {scope}")
    print(f"Alerts evaluated  : {len(evaluated_alerts)}")
    print()

    true_positives = []
    false_negatives = []

    print(f"{'Attacker IP':<14} {'Expected attack type':<24} {'Result':<10} {'Confidence'}")
    print("-" * 72)
    for item in expected:
        ip, attack_type = item["source_ip"], item["attack_type"]
        key = (ip, attack_type)
        if key in actual:
            true_positives.append(item)
            print(f"{ip:<14} {attack_type:<24} {'CAUGHT':<10} {actual[key]:.2f}")
        else:
            false_negatives.append(item)
            print(f"{ip:<14} {attack_type:<24} {'MISSED':<10} --")

    # False positives on benign IPs: track BOTH individual alert records and unique benign IPs.
    false_positive_alerts = [
        alert for alert in evaluated_alerts if alert.source_ip in benign_ips
    ]
    false_positive_ips = sorted({alert.source_ip for alert in false_positive_alerts})

    print()
    print("-" * 72)
    print(
        f"False positive alerts (benign IPs): {len(false_positive_alerts)} "
        f"across {len(false_positive_ips)} unique benign IP(s)"
    )
    for alert in false_positive_alerts:
        print(f"  {alert.source_ip:<14} flagged as {alert.attack_type} "
              f"(confidence {alert.confidence:.2f})")

    tp = len(true_positives)
    fn = len(false_negatives)
    fp_alerts = len(false_positive_alerts)
    fp_ips = len(false_positive_ips)

    alert_precision, recall, alert_f1 = _compute_pr_f1(tp, fp_alerts, fn)
    ip_precision, _, ip_f1 = _compute_pr_f1(tp, fp_ips, fn)

    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"True Positives  : {tp} / {len(expected)} expected attacks caught")
    print(f"False Negatives : {fn} (attacks missed)")
    print(f"FP (Alerts)     : {fp_alerts} alert(s) on benign IPs")
    print(f"FP (Unique IPs) : {fp_ips} unique benign IP(s) flagged")
    print(
        f"Precision (Alert): {alert_precision:.2%}"
        if alert_precision == alert_precision
        else "Precision (Alert): n/a"
    )
    print(
        f"Precision (IP)   : {ip_precision:.2%}"
        if ip_precision == ip_precision
        else "Precision (IP)   : n/a"
    )
    print(f"Recall          : {recall:.2%}" if recall == recall else "Recall          : n/a")
    print(f"F1 (Alert)      : {alert_f1:.2%}" if alert_f1 == alert_f1 else "F1 (Alert)      : n/a")
    print(f"F1 (IP)         : {ip_f1:.2%}" if ip_f1 == ip_f1 else "F1 (IP)         : n/a")
    print("=" * 72)
    print("Copy the Precision / Recall / F1 lines above directly into your")
    print("SIH report as your measured detection accuracy.")
    print("=" * 72)

    return {
        "ground_truth_path": ground_truth_path,
        "scope": scope,
        "total_alerts": len(evaluated_alerts),
        "true_positives": tp,
        "expected_attacks": len(expected),
        "false_negatives": fn,
        "false_positives": fp_alerts,
        "false_positive_alerts": fp_alerts,
        "false_positive_ips": fp_ips,
        "precision": float(alert_precision) if alert_precision == alert_precision else None,
        "alert_precision": float(alert_precision) if alert_precision == alert_precision else None,
        "ip_precision": float(ip_precision) if ip_precision == ip_precision else None,
        "recall": float(recall) if recall == recall else None,
        "f1": float(alert_f1) if alert_f1 == alert_f1 else None,
        "alert_f1": float(alert_f1) if alert_f1 == alert_f1 else None,
        "ip_f1": float(ip_f1) if ip_f1 == ip_f1 else None,
        "detailed_results": [
            {
                "source_ip": item["source_ip"],
                "attack_type": item["attack_type"],
                "caught": (item["source_ip"], item["attack_type"]) in actual,
                "confidence": actual.get((item["source_ip"], item["attack_type"]), 0.0),
            }
            for item in expected
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate detection accuracy against a ground-truth manifest"
    )
    parser.add_argument(
        "ground_truth_path",
        help="Path to the *.ground_truth.json file produced by generate_synthetic_traffic.py"
    )
    parser.add_argument(
        "--all-alerts",
        action="store_true",
        help="Evaluate against all alerts in the database instead of scoping to the latest replay",
    )
    args = parser.parse_args()
    validate(args.ground_truth_path, use_latest_replay=not args.all_alerts)


if __name__ == "__main__":
    main()
