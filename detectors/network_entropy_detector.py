"""
CTD — Network-Wide Source IP Entropy & Distributed UDP Flood Detector

Detects distributed, spoofed-source UDP floods across observation windows
by analyzing aggregate traffic volume combined with Shannon entropy of
source IP distributions.

When attackers spoof random source IPs, each individual source sends only
a few packets, evading per-source thresholds. This detector operates at the
network level to detect high aggregate volume combined with abnormally
dispersed, high-entropy source distributions.

CRITICAL PASSIVE MONITORING CONSTRAINTS:
- SentinelFlow-CTD operates strictly passively: no active packet transmission,
  no outbound probes, no inline packet dropping, no firewall/routing rules.
- Only metadata collected over bounded observation windows is inspected.
"""

import math
from typing import Dict, Mapping, Optional, Tuple
from detectors.detection_result import DetectionResult


# ---------------------------------------------------------------------
# Configurable Thresholds (Defaults)
# ---------------------------------------------------------------------

# Minimum aggregate UDP packet count across the window to evaluate
MIN_AGGREGATE_UDP_PACKETS: int = 40

# Minimum aggregate UDP packet rate (packets / second)
MIN_AGGREGATE_UDP_RATE: float = 40.0

# Minimum aggregate UDP bandwidth footprint (bytes / second: 40 KB/s)
MIN_AGGREGATE_UDP_BYTES_PER_SECOND: float = 40_000.0

# Minimum distinct source IPs required to consider a distributed attack
MIN_UNIQUE_SOURCES: int = 10

# Minimum normalized Shannon entropy (0.0 to 1.0)
MIN_NORMALIZED_SOURCE_ENTROPY: float = 0.75

# Minimum absolute Shannon entropy in bits (e.g., log2(10) ≈ 3.32 bits)
MIN_SOURCE_ENTROPY_BITS: float = 3.0

# Maximum average packets per source (spoofed traffic disperses 1-few packets per IP)
MAX_MEAN_PACKETS_PER_SOURCE: float = 15.0

# Minimum aggregate UDP dominance (UDP packets / total packets)
MIN_UDP_PACKET_RATIO: float = 0.70


def calculate_shannon_entropy(counts: Mapping[str, int]) -> Tuple[float, float]:
    """
    Calculate absolute Shannon entropy (in bits) and normalized entropy [0.0, 1.0].

    H = - sum(p_i * log2(p_i))
    H_norm = H / log2(K) where K = number of distinct categories (K > 1).
    """
    if not counts:
        return 0.0, 0.0

    total = sum(counts.values())
    if total <= 0:
        return 0.0, 0.0

    k = len(counts)
    if k <= 1:
        return 0.0, 0.0

    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    max_entropy = math.log2(k)
    normalized = entropy / max_entropy if max_entropy > 0 else 0.0
    return entropy, normalized


def detect_distributed_udp_flood(
    features: Dict,
    thresholds: Optional[Dict] = None,
) -> DetectionResult:
    """
    Evaluate network-wide aggregate features for distributed, spoofed-source
    UDP volumetric floods.

    Parameters:
        features: Network-level feature dictionary containing:
            - udp_packets: int
            - packets: int
            - bytes: int (or udp_bytes: int)
            - udp_rate: Optional[float]
            - bytes_per_second: Optional[float] (or udp_bytes_per_second)
            - unique_sources: int
            - source_ip_entropy: Optional[float]
            - normalized_source_entropy: Optional[float]
            - source_counts: Optional[Mapping[str, int]]
            - udp_source_counts: Optional[Mapping[str, int]]
            - udp_packet_ratio: Optional[float]
            - mean_packets_per_source: Optional[float]
            - window_duration: Optional[float]
        thresholds: Optional dictionary overriding any default threshold.

    Returns:
        DetectionResult with detected, attack_type="DISTRIBUTED_UDP_FLOOD",
        severity, score, confidence, and reasons.
    """
    cfg = {
        "min_aggregate_udp_packets": MIN_AGGREGATE_UDP_PACKETS,
        "min_aggregate_udp_rate": MIN_AGGREGATE_UDP_RATE,
        "min_aggregate_udp_bytes_per_second": MIN_AGGREGATE_UDP_BYTES_PER_SECOND,
        "min_unique_sources": MIN_UNIQUE_SOURCES,
        "min_normalized_source_entropy": MIN_NORMALIZED_SOURCE_ENTROPY,
        "min_source_entropy_bits": MIN_SOURCE_ENTROPY_BITS,
        "max_mean_packets_per_source": MAX_MEAN_PACKETS_PER_SOURCE,
        "min_udp_packet_ratio": MIN_UDP_PACKET_RATIO,
    }
    if thresholds:
        cfg.update(thresholds)

    reasons = []
    score = 0

    # -----------------------------------------------------------------
    # 1. Base traffic extraction
    # -----------------------------------------------------------------
    udp_packets = features.get("udp_packets", 0)
    total_packets = features.get("packets", udp_packets)
    duration = max(features.get("window_duration", 1.0), 0.000001)

    udp_rate = features.get("udp_rate")
    if udp_rate is None:
        udp_rate = udp_packets / duration

    # Extract or calculate bandwidth
    udp_bytes = features.get("udp_bytes", features.get("bytes", 0))
    bytes_per_second = features.get(
        "udp_bytes_per_second",
        features.get("bytes_per_second", udp_bytes / duration if udp_bytes > 0 else 0.0),
    )

    # UDP dominance ratio
    udp_packet_ratio = features.get("udp_packet_ratio")
    if udp_packet_ratio is None:
        udp_packet_ratio = udp_packets / max(total_packets, 1) if total_packets > 0 else 0.0

    # -----------------------------------------------------------------
    # 2. Extract or compute UDP source diversity and entropy
    # -----------------------------------------------------------------
    udp_source_counts = features.get("udp_source_counts")
    source_counts = (
        udp_source_counts
        if udp_source_counts is not None
        else features.get("source_counts")
    )
    unique_sources = features.get("udp_sources")
    if unique_sources is None:
        unique_sources = features.get(
            "unique_sources",
            len(source_counts) if source_counts else 0,
        )

    # Derive UDP-scoped entropy when present; fall back to global keys
    # only for standalone callers that do not pass UDP-specific keys.
    entropy_bits = features.get("udp_source_entropy")
    if entropy_bits is None:
        entropy_bits = features.get("source_ip_entropy")

    normalized_entropy = features.get("udp_normalized_entropy")
    if normalized_entropy is None:
        normalized_entropy = features.get("normalized_source_entropy")

    if (entropy_bits is None or normalized_entropy is None) and source_counts:
        calc_entropy, calc_norm = calculate_shannon_entropy(source_counts)
        if entropy_bits is None:
            entropy_bits = calc_entropy
        if normalized_entropy is None:
            normalized_entropy = calc_norm

    entropy_bits = entropy_bits or 0.0
    normalized_entropy = normalized_entropy or 0.0

    # Average packets per UDP source
    mean_packets_per_source = features.get("mean_udp_packets_per_source")
    if mean_packets_per_source is None:
        mean_packets_per_source = features.get(
            "mean_packets_per_source",
            udp_packets / max(unique_sources, 1) if unique_sources > 0 else 0.0,
        )

    # -----------------------------------------------------------------
    # Gating Check 1: Insufficient samples / low traffic
    # A distributed flood must have both sufficient aggregate packets
    # and sufficient distinct sources.
    # -----------------------------------------------------------------
    if udp_packets < cfg["min_aggregate_udp_packets"] or unique_sources < cfg["min_unique_sources"]:
        return DetectionResult(
            detected=False,
            attack_type=None,
            severity="NONE",
            score=0,
            confidence=0.0,
            reasons=[],
        )

    # -----------------------------------------------------------------
    # Gating Check 2: Low entropy / single-source domination
    # If entropy is low, this is NOT a distributed spoofed attack
    # (single-source floods are handled by the per-source detector).
    # -----------------------------------------------------------------
    if normalized_entropy < cfg["min_normalized_source_entropy"] and entropy_bits < cfg["min_source_entropy_bits"]:
        return DetectionResult(
            detected=False,
            attack_type=None,
            severity="NONE",
            score=0,
            confidence=0.0,
            reasons=[],
        )

    # -----------------------------------------------------------------
    # Criterion 1: High aggregate UDP packet rate
    # -----------------------------------------------------------------
    if udp_rate >= cfg["min_aggregate_udp_rate"] and udp_packets >= cfg["min_aggregate_udp_packets"]:
        score += 1
        reasons.append(
            f"high aggregate UDP traffic rate ({udp_rate:.1f} pkts/sec >= {cfg['min_aggregate_udp_rate']})"
        )

    # -----------------------------------------------------------------
    # Criterion 2: High aggregate volumetric bandwidth
    # -----------------------------------------------------------------
    if bytes_per_second >= cfg["min_aggregate_udp_bytes_per_second"]:
        score += 1
        reasons.append(
            f"high aggregate UDP bandwidth ({bytes_per_second / 1024:.1f} KB/s >= {cfg['min_aggregate_udp_bytes_per_second'] / 1024:.1f} KB/s)"
        )

    # -----------------------------------------------------------------
    # Criterion 3: High source IP Shannon entropy
    # -----------------------------------------------------------------
    if (
        normalized_entropy >= cfg["min_normalized_source_entropy"]
        and entropy_bits >= cfg["min_source_entropy_bits"]
    ):
        score += 1
        reasons.append(
            f"abnormally high source IP entropy (H={entropy_bits:.2f} bits, H_norm={normalized_entropy:.2f} >= {cfg['min_normalized_source_entropy']})"
        )

    # -----------------------------------------------------------------
    # Criterion 4: Dispersed multi-source footprint (spoofed dispersion)
    # -----------------------------------------------------------------
    if (
        unique_sources >= cfg["min_unique_sources"]
        and mean_packets_per_source <= cfg["max_mean_packets_per_source"]
    ):
        score += 1
        reasons.append(
            f"dispersed multi-source footprint ({unique_sources} distinct sources, {mean_packets_per_source:.1f} mean pkts/source)"
        )

    # -----------------------------------------------------------------
    # Criterion 5: UDP protocol dominance across the network
    # -----------------------------------------------------------------
    if udp_packet_ratio >= cfg["min_udp_packet_ratio"]:
        score += 1
        reasons.append(
            f"high network-wide UDP dominance ({udp_packet_ratio:.2f} of total traffic >= {cfg['min_udp_packet_ratio']})"
        )

    # Passive monitoring observation note
    reasons.append(
        "passive observation of network-wide source entropy anomaly; no active probing or mitigation conducted"
    )

    # -----------------------------------------------------------------
    # Final Decision, Severity and Confidence
    # -----------------------------------------------------------------
    # Must achieve at least 3 criteria to trigger
    detected = score >= 3

    if score >= 4 and (udp_rate >= 100.0 or bytes_per_second >= 80_000.0):
        severity = "HIGH"
    elif score >= 3:
        severity = "MEDIUM"
    else:
        severity = "NONE"

    if detected:
        # Confidence scaled to [0.65, 1.00]
        confidence = min(0.65 + (score - 3) * 0.15, 1.0)
    else:
        confidence = min(score / 5.0, 0.49)

    return DetectionResult(
        detected=detected,
        attack_type="DISTRIBUTED_UDP_FLOOD" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )


# Alias for compatibility
detect_network_entropy_flood = detect_distributed_udp_flood
