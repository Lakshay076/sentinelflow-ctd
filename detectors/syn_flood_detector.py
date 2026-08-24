"""
CTD — SYN Flood Detector

Detects SYN-flood-like behavior using aggregated
network metadata.

No packet payloads are inspected.
"""

from typing import Dict

from detectors.detection_result import DetectionResult


MIN_SYN_RATIO = 0.80
MIN_SYN_RATE = 50.0
MIN_FLOWS_PER_SECOND = 50.0


def detect_syn_flood(features: Dict) -> DetectionResult:

    reasons = []
    score = 0

    syn_ratio = features.get(
        "syn_packet_ratio", 0.0
    )

    syn_rate = features.get(
        "syn_rate", 0.0
    )

    flows_per_second = features.get(
        "flows_per_second", 0.0
    )

    # -----------------------------------------------------
    # High SYN ratio
    # -----------------------------------------------------

    if syn_ratio >= MIN_SYN_RATIO:

        score += 1

        reasons.append(
            f"high SYN packet ratio "
            f"({syn_ratio:.2f})"
        )

    # -----------------------------------------------------
    # High SYN rate
    # -----------------------------------------------------

    if syn_rate >= MIN_SYN_RATE:

        score += 1

        reasons.append(
            f"high SYN rate "
            f"({syn_rate:.2f} SYN/sec)"
        )

    # -----------------------------------------------------
    # High flow creation rate
    # -----------------------------------------------------

    if flows_per_second >= MIN_FLOWS_PER_SECOND:

        score += 1

        reasons.append(
            f"high flow creation rate "
            f"({flows_per_second:.2f} flows/sec)"
        )

    # -----------------------------------------------------
    # Final decision
    # -----------------------------------------------------

    detected = score >= 2

    if score >= 3:

        severity = "HIGH"

    elif score >= 2:

        severity = "MEDIUM"

    else:

        severity = "NONE"

    confidence = score / 3.0

    return DetectionResult(
        detected=detected,
        attack_type="SYN_FLOOD" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
