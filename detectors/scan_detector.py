"""
CTD — Port Scan Detector (Vertical & Horizontal Reconnaissance)

Detects reconnaissance activity using aggregated network metadata only:
1. Vertical Port Scan: A source IP probing multiple destination ports
   on a single or few destination hosts (service discovery).
2. Fast Horizontal Host Sweep: A source IP probing a single or few destination
   ports across multiple distinct destination IPs within an observation window.
3. Slow-and-Low Horizontal Host Sweep: A source IP probing destination hosts
   at a stealthy, low rate across the rolling 10-second BehaviorWindow.

No packet payloads are inspected.
"""

from typing import Dict, Optional
from detectors.detection_result import DetectionResult


# ---------------------------------------------------------------------
# Configurable Thresholds (Defaults)
# ---------------------------------------------------------------------

# Vertical Scan: Port diversity on target host(s)
MIN_DESTINATION_PORTS: int = 5
MIN_FLOWS: int = 5
MIN_SYN_RATIO: float = 0.60
MIN_FLOWS_PER_SECOND: float = 5.0

# Horizontal Scan (Fast): Host fan-out across multiple destination IPs (1s window)
MIN_DESTINATION_HOSTS: int = 8          # Minimum unique destination IPs to consider host sweep
MAX_HORIZONTAL_PORTS: int = 3           # Concentrated port footprint across target hosts
MIN_HORIZONTAL_FLOWS: int = 8           # Minimum connection attempts
MIN_HORIZONTAL_SYN_RATIO: float = 0.50  # Elevated connection-attempt ratio (not established sessions)
MIN_HORIZONTAL_FLOW_RATE: float = 5.0   # Rate of connection attempts across hosts (flows/sec)

# Horizontal Scan (Slow-and-Low): Low-rate host sweep across rolling window (10s window)
MIN_SLOW_SCAN_HOSTS: int = 8          # Minimum unique destination IPs across rolling window
MAX_SLOW_SCAN_PORTS: int = 3          # Concentrated port footprint across target hosts
MIN_SLOW_SCAN_FLOWS: int = 8          # Minimum connection attempts across rolling window
MIN_SLOW_SCAN_SYN_RATIO: float = 0.50 # Elevated connection-attempt ratio (reconnaissance vs data transfer)
MIN_SLOW_SCAN_SYN_PACKETS: int = 6    # Minimum raw SYN packets to avoid triggering on sparse/idle sources


def detect_port_scan(
    features: Dict,
    thresholds: Optional[Dict] = None,
) -> DetectionResult:
    """
    Evaluate feature vector for vertical port scanning, fast horizontal host sweeps,
    or slow-and-low reconnaissance across a rolling behavioral window.

    Parameters:
        features: Dictionary containing source features:
            - unique_destination_ports: int
            - unique_destinations: int
            - active_flows: int
            - syn_packet_ratio: float
            - flows_per_second: float
            - ports_per_destination: Optional[float]
            - rolling_unique_destinations: Optional[int]
            - rolling_unique_destination_ports: Optional[int]
            - rolling_active_flows: Optional[int]
            - rolling_tcp_syn: Optional[int]
            - rolling_syn_ratio: Optional[float]
            - rolling_ports_per_destination: Optional[float]
        thresholds: Optional dictionary overriding any default threshold.

    Returns:
        DetectionResult with detected, attack_type="PORT_SCAN",
        severity, score, confidence, and reasons.
    """
    cfg = {
        "min_destination_ports": MIN_DESTINATION_PORTS,
        "min_flows": MIN_FLOWS,
        "min_syn_ratio": MIN_SYN_RATIO,
        "min_flows_per_second": MIN_FLOWS_PER_SECOND,
        "min_destination_hosts": MIN_DESTINATION_HOSTS,
        "max_horizontal_ports": MAX_HORIZONTAL_PORTS,
        "min_horizontal_flows": MIN_HORIZONTAL_FLOWS,
        "min_horizontal_syn_ratio": MIN_HORIZONTAL_SYN_RATIO,
        "min_horizontal_flow_rate": MIN_HORIZONTAL_FLOW_RATE,
        "min_slow_scan_hosts": MIN_SLOW_SCAN_HOSTS,
        "max_slow_scan_ports": MAX_SLOW_SCAN_PORTS,
        "min_slow_scan_flows": MIN_SLOW_SCAN_FLOWS,
        "min_slow_scan_syn_ratio": MIN_SLOW_SCAN_SYN_RATIO,
        "min_slow_scan_syn_packets": MIN_SLOW_SCAN_SYN_PACKETS,
    }
    if thresholds:
        cfg.update(thresholds)

    reasons = []
    score = 0

    unique_ports = features.get("unique_destination_ports", 0)
    unique_destinations = features.get("unique_destinations", 0)
    active_flows = features.get("active_flows", 0)
    syn_ratio = features.get("syn_packet_ratio", 0.0)
    flows_per_second = features.get("flows_per_second", 0.0)
    ports_per_dest = features.get(
        "ports_per_destination",
        unique_ports / max(unique_destinations, 1) if unique_destinations > 0 else 0.0,
    )

    # Rolling window behavioral features (for slow-and-low reconnaissance)
    rolling_destinations = features.get("rolling_unique_destinations")
    rolling_ports = features.get("rolling_unique_destination_ports")
    rolling_flows = features.get("rolling_active_flows")
    rolling_syn = features.get("rolling_tcp_syn")
    rolling_syn_ratio = features.get("rolling_syn_ratio")
    rolling_ppd = features.get("rolling_ports_per_destination")

    # If rolling metrics are present, use them for slow sweep evaluation;
    # otherwise fall back to top-level feature metrics.
    slow_destinations = rolling_destinations if rolling_destinations is not None else unique_destinations
    slow_ports = rolling_ports if rolling_ports is not None else unique_ports
    slow_flows = rolling_flows if rolling_flows is not None else active_flows
    slow_syn_ratio = rolling_syn_ratio if rolling_syn_ratio is not None else syn_ratio
    slow_syn_packets = (
        rolling_syn
        if rolling_syn is not None
        else features.get("tcp_syn", int(slow_flows * slow_syn_ratio))
    )
    slow_ppd = (
        rolling_ppd
        if rolling_ppd is not None
        else (slow_ports / max(slow_destinations, 1) if slow_destinations > 0 else 0.0)
    )

    # -----------------------------------------------------------------
    # 1. Evaluate Port Diversity (Vertical Reconnaissance)
    # -----------------------------------------------------------------
    if unique_ports >= cfg["min_destination_ports"]:
        score += 1
        reasons.append(
            f"high destination-port diversity ({unique_ports} ports)"
        )

    # -----------------------------------------------------------------
    # 2. Evaluate Host Fan-Out (Horizontal Reconnaissance - Fast)
    # -----------------------------------------------------------------
    if unique_destinations >= cfg["min_destination_hosts"]:
        score += 1
        reasons.append(
            f"high destination-host fan-out ({unique_destinations} hosts)"
        )

    # -----------------------------------------------------------------
    # 3. Connection Attempts
    # -----------------------------------------------------------------
    if active_flows >= cfg["min_flows"]:
        score += 1
        reasons.append(
            f"multiple connection attempts ({active_flows} flows)"
        )

    # -----------------------------------------------------------------
    # 4. Connection Rate
    # -----------------------------------------------------------------
    if flows_per_second >= cfg["min_flows_per_second"]:
        score += 1
        reasons.append(
            f"high connection rate ({flows_per_second:.2f} flows/sec)"
        )

    # -----------------------------------------------------------------
    # 5. SYN Attempt Dominance
    # -----------------------------------------------------------------
    if syn_ratio >= cfg["min_syn_ratio"]:
        score += 1
        reasons.append(
            f"high SYN ratio ({syn_ratio:.2f})"
        )
    elif (
        syn_ratio >= cfg["min_horizontal_syn_ratio"]
        and unique_destinations >= cfg["min_destination_hosts"]
    ):
        score += 1
        reasons.append(
            f"elevated SYN attempt ratio during host sweep ({syn_ratio:.2f})"
        )

    # -----------------------------------------------------------------
    # 6. Targeted Horizontal Sweep Profile (Fast)
    # Probing one or few specific ports across many destination hosts
    # -----------------------------------------------------------------
    is_fast_horizontal_profile = (
        unique_destinations >= cfg["min_destination_hosts"]
        and (0 < unique_ports <= cfg["max_horizontal_ports"] or ports_per_dest <= 1.0)
    )
    if is_fast_horizontal_profile:
        score += 1
        reasons.append(
            f"targeted horizontal port sweep profile ({unique_ports} port(s) across {unique_destinations} hosts, {ports_per_dest:.2f} ports/host)"
        )

    # -----------------------------------------------------------------
    # Decision Rules: Vertical vs. Fast Horizontal vs. Slow Horizontal
    # -----------------------------------------------------------------
    # Vertical Scan: Probing many ports on single/few targets with high SYN ratio
    is_vertical_scan = (
        unique_ports >= cfg["min_destination_ports"]
        and syn_ratio >= cfg["min_syn_ratio"]
        and score >= 2
    )

    # Fast Horizontal Scan: High host fan-out & connection rate in current window
    is_fast_horizontal_scan = (
        unique_destinations >= cfg["min_destination_hosts"]
        and is_fast_horizontal_profile
        and syn_ratio >= cfg["min_horizontal_syn_ratio"]
        and active_flows >= cfg["min_horizontal_flows"]
        and score >= 3
    )

    # Slow-and-Low Horizontal Scan: Low-rate host sweep across rolling window (10s)
    is_slow_horizontal_profile = (
        slow_destinations >= cfg["min_slow_scan_hosts"]
        and (0 < slow_ports <= cfg["max_slow_scan_ports"] or slow_ppd <= 1.0)
    )
    is_slow_horizontal_scan = (
        slow_destinations >= cfg["min_slow_scan_hosts"]
        and is_slow_horizontal_profile
        and slow_syn_ratio >= cfg["min_slow_scan_syn_ratio"]
        and slow_flows >= cfg["min_slow_scan_flows"]
        and slow_syn_packets >= cfg["min_slow_scan_syn_packets"]
    )

    if is_slow_horizontal_scan:
        slow_score = 3
        if slow_destinations >= 12 and slow_syn_packets >= 10:
            slow_score = 4
        score = max(score, slow_score)
        reasons.append(
            f"slow-and-low horizontal sweep detected over rolling window "
            f"({slow_destinations} hosts, {slow_ports} port(s), "
            f"SYN ratio {slow_syn_ratio:.2f}, {slow_syn_packets} SYNs)"
        )

    detected = is_vertical_scan or is_fast_horizontal_scan or is_slow_horizontal_scan

    # Clarify pattern in reasons
    if is_vertical_scan and (is_fast_horizontal_scan or is_slow_horizontal_scan):
        reasons.append(
            "hybrid reconnaissance pattern (both vertical port diversity and horizontal host fan-out)"
        )
    elif is_fast_horizontal_scan:
        reasons.append(
            "horizontal reconnaissance sweep (probing single/few ports across multiple destination hosts)"
        )
    elif is_slow_horizontal_scan:
        reasons.append(
            "slow-and-low horizontal reconnaissance sweep (probing across destination hosts over rolling window)"
        )
    elif is_vertical_scan:
        reasons.append(
            "vertical reconnaissance pattern (probing multiple destination ports on target host)"
        )

    # -----------------------------------------------------------------
    # Severity & Confidence
    # -----------------------------------------------------------------
    if not detected:
        severity = "NONE"
    elif score >= 4:
        severity = "HIGH"
    elif score >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    confidence = min(score / 4.0, 1.0) if detected else min(score / 4.0, 0.49)

    return DetectionResult(
        detected=detected,
        attack_type="PORT_SCAN" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
