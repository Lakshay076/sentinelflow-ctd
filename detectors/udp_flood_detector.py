"""
CTD — UDP Volumetric Flood & Reflection Pattern Detector

Detects high-volume UDP floods and suspicious reflection/amplification
patterns using aggregated network metadata only.

No packet payloads are inspected.

CRITICAL PASSIVE MONITORING CONSTRAINTS:
- MONI operates purely passively: no packets generated on live networks,
  no outbound probes, no inline drops, no firewall rules altered.
- When only one direction of traffic is visible (unidirectional mirror/tap),
  do NOT claim a verified amplification ratio; flag as suspicious UDP
  volumetric activity.
- When both request and response legs are observed in mirrored traffic,
  infer amplification patterns from observed byte/packet relationships.
"""

from typing import Dict, Optional, Set
from detectors.detection_result import DetectionResult


# ---------------------------------------------------------------------
# Configurable Thresholds (Defaults)
# ---------------------------------------------------------------------

# Minimum UDP packet rate (packets per second)
MIN_UDP_RATE: float = 50.0

# Minimum ratio of UDP packets to total packets (e.g., >= 80% UDP)
MIN_UDP_RATIO: float = 0.80

# Minimum bandwidth footprint (bytes per second, e.g. 50 KB/s)
MIN_UDP_BYTES_PER_SECOND: float = 50_000.0

# Minimum absolute UDP packet count to prevent false positives on tiny samples
MIN_UDP_PACKETS: int = 20

# Minimum flows per second (rapid creation of ephemeral UDP flows/sockets)
MIN_FLOWS_PER_SECOND: float = 20.0

# Port concentration threshold: victim or reflector port saturation
MAX_PORTS_FOR_CONCENTRATION: int = 2

# Well-known UDP amplification/reflection service ports
WELL_KNOWN_REFLECTION_PORTS: Set[int] = {
    17,     # QOTD
    19,     # CharGEN
    53,     # DNS
    123,    # NTP
    161,    # SNMP
    389,    # CLDAP
    1900,   # SSDP
    3702,   # WS-Discovery
    5353,   # mDNS
    11211,  # Memcached
}


def detect_udp_flood(
    features: Dict,
    thresholds: Optional[Dict] = None,
) -> DetectionResult:
    """
    Evaluate feature vector for UDP volumetric flood or reflection activity.

    Parameters:
        features: Dictionary containing source or window features:
            - udp_packets: int
            - packets: int
            - bytes: int (or bytes_per_second: float)
            - bytes_received: int
            - outbound_inbound_ratio: float
            - udp_rate: Optional[float]
            - udp_packet_ratio: Optional[float]
            - unique_destinations: Optional[int]
            - unique_destination_ports: Optional[int]
            - destination_ports: Optional[Set[int]]
            - flows_per_second: Optional[float]
            - window_duration: Optional[float]
        thresholds: Optional dictionary overriding any default threshold.

    Returns:
        DetectionResult with detected, attack_type="UDP_FLOOD",
        severity, score, confidence, and reasons.
    """
    cfg = {
        "min_udp_rate": MIN_UDP_RATE,
        "min_udp_ratio": MIN_UDP_RATIO,
        "min_udp_bytes_per_second": MIN_UDP_BYTES_PER_SECOND,
        "min_udp_packets": MIN_UDP_PACKETS,
        "min_flows_per_second": MIN_FLOWS_PER_SECOND,
        "max_ports_for_concentration": MAX_PORTS_FOR_CONCENTRATION,
    }
    if thresholds:
        cfg.update(thresholds)

    reasons = []
    score = 0

    # -----------------------------------------------------------------
    # 1. Extract base metrics
    # -----------------------------------------------------------------
    udp_packets = features.get("udp_packets", 0)
    total_packets = features.get("packets", udp_packets)
    duration = max(features.get("window_duration", 1.0), 0.000001)

    # UDP rate (packets / sec)
    udp_rate = features.get("udp_rate")
    if udp_rate is None:
        udp_rate = udp_packets / duration

    # UDP ratio (udp_packets / total_packets)
    udp_packet_ratio = features.get("udp_packet_ratio")
    if udp_packet_ratio is None:
        udp_packet_ratio = udp_packets / max(total_packets, 1) if total_packets > 0 else 0.0

    # Bytes and bandwidth
    bytes_sent = features.get("bytes", 0)
    bytes_received = features.get("bytes_received", 0)
    bytes_per_second = features.get(
        "bytes_per_second",
        bytes_sent / duration if bytes_sent > 0 else 0.0,
    )

    # Port and destination diversity
    unique_ports = features.get("unique_destination_ports", 0)
    dest_ports_set = features.get("destination_ports")
    flows_per_second = features.get("flows_per_second", 0.0)

    # If no UDP traffic was observed, return immediately
    if udp_packets == 0 and udp_rate == 0.0:
        return DetectionResult(
            detected=False,
            attack_type=None,
            severity="NONE",
            score=0,
            confidence=0.0,
            reasons=[],
        )

    # -----------------------------------------------------------------
    # Criterion 1: High UDP packet rate
    # -----------------------------------------------------------------
    if udp_rate >= cfg["min_udp_rate"] and udp_packets >= cfg["min_udp_packets"]:
        score += 1
        reasons.append(
            f"high UDP packet rate ({udp_rate:.1f} UDP pkts/sec >= {cfg['min_udp_rate']})"
        )

    # -----------------------------------------------------------------
    # Criterion 2: High UDP packet ratio
    # -----------------------------------------------------------------
    if udp_packet_ratio >= cfg["min_udp_ratio"] and udp_packets >= cfg["min_udp_packets"]:
        score += 1
        reasons.append(
            f"high UDP packet dominance ({udp_packet_ratio:.2f} of total traffic >= {cfg['min_udp_ratio']})"
        )

    # -----------------------------------------------------------------
    # Criterion 3: High volumetric bandwidth
    # -----------------------------------------------------------------
    if bytes_per_second >= cfg["min_udp_bytes_per_second"] and udp_packets >= cfg["min_udp_packets"]:
        score += 1
        reasons.append(
            f"high volumetric UDP bandwidth ({bytes_per_second / 1024:.1f} KB/s >= {cfg['min_udp_bytes_per_second'] / 1024:.1f} KB/s)"
        )

    # -----------------------------------------------------------------
    # Criterion 4: Destination port concentration or reflection targeting
    # -----------------------------------------------------------------
    reflection_ports_hit = set()
    if isinstance(dest_ports_set, (set, list, tuple)):
        reflection_ports_hit = set(dest_ports_set) & WELL_KNOWN_REFLECTION_PORTS

    is_port_concentrated = (
        0 < unique_ports <= cfg["max_ports_for_concentration"]
        and udp_packets >= cfg["min_udp_packets"]
    )

    if reflection_ports_hit:
        score += 1
        ports_str = ", ".join(str(p) for p in sorted(reflection_ports_hit))
        reasons.append(
            f"traffic targets known UDP reflection/amplification service port(s): {ports_str}"
        )
    elif is_port_concentrated:
        score += 1
        reasons.append(
            f"concentrated UDP target port profile ({unique_ports} destination port(s))"
        )

    # -----------------------------------------------------------------
    # Criterion 5: High flow creation rate
    # -----------------------------------------------------------------
    if flows_per_second >= cfg["min_flows_per_second"] and udp_packets >= cfg["min_udp_packets"]:
        score += 1
        reasons.append(
            f"high UDP flow creation rate ({flows_per_second:.1f} flows/sec >= {cfg['min_flows_per_second']})"
        )

    # -----------------------------------------------------------------
    # Passive Reflection / Amplification Inference Constraint
    # -----------------------------------------------------------------
    outbound_inbound_ratio = features.get("outbound_inbound_ratio", 0.0)
    has_bidirectional = bytes_received > 0 and bytes_sent > 0

    if has_bidirectional and (outbound_inbound_ratio >= 5.0 or (bytes_received / max(bytes_sent, 1)) >= 5.0):
        effective_ratio = max(outbound_inbound_ratio, bytes_received / max(bytes_sent, 1))
        reasons.append(
            f"asymmetric byte ratio ({effective_ratio:.1f}:1) suggestive of amplification pattern across observed bidirectional traffic"
        )
    elif udp_packets >= cfg["min_udp_packets"]:
        reasons.append(
            "unidirectional volumetric UDP traffic (amplification ratio unverified under one-way visibility)"
        )

    # -----------------------------------------------------------------
    # Final Decision, Severity and Confidence
    # -----------------------------------------------------------------
    detected = score >= 2

    if score >= 4 or (score >= 3 and (bytes_per_second >= 100_000.0 or udp_rate >= 100.0)):
        severity = "HIGH"
    elif score >= 2:
        severity = "MEDIUM"
    else:
        severity = "NONE"

    if detected:
        # Normalize confidence to [0.60, 1.00] based on score
        confidence = min(0.60 + (score - 2) * 0.15, 1.0)
    else:
        confidence = min(score / 4.0, 0.49)

    return DetectionResult(
        detected=detected,
        attack_type="UDP_FLOOD" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
