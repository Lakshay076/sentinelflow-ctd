"""
CTD — Port Scan Detector
"""

from typing import Dict

from detectors.detection_result import DetectionResult


MIN_DESTINATION_PORTS = 5
MIN_FLOWS = 5
MIN_SYN_RATIO = 0.60
MIN_FLOWS_PER_SECOND = 5.0


def detect_port_scan(features: Dict) -> DetectionResult:

    reasons = []
    score = 0

    unique_ports = features.get(
        "unique_destination_ports", 0
    )

    active_flows = features.get(
        "active_flows", 0
    )

    syn_ratio = features.get(
        "syn_packet_ratio", 0.0
    )

    flows_per_second = features.get(
        "flows_per_second", 0.0
    )

    if unique_ports >= MIN_DESTINATION_PORTS:

        score += 1

        reasons.append(
            f"high destination-port diversity "
            f"({unique_ports} ports)"
        )

    if active_flows >= MIN_FLOWS:

        score += 1

        reasons.append(
            f"multiple connection attempts "
            f"({active_flows} flows)"
        )

    if syn_ratio >= MIN_SYN_RATIO:

        score += 1

        reasons.append(
            f"high SYN ratio "
            f"({syn_ratio:.2f})"
        )

    if flows_per_second >= MIN_FLOWS_PER_SECOND:

        score += 1

        reasons.append(
            f"high connection rate "
            f"({flows_per_second:.2f} flows/sec)"
        )

    # -----------------------------------------------------
    # Final decision
    # -----------------------------------------------------

    detected = (
        unique_ports >= MIN_DESTINATION_PORTS
        and score >= 2
    )

    if not detected:
        severity = "NONE"
    elif score >= 4:
        severity = "HIGH"
    elif score >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    confidence = score / 4.0

    return DetectionResult(
        detected=detected,
        attack_type="PORT_SCAN" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
