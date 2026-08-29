"""
CTD — DGA / DNS Tunnelling Detector

Flags sources whose DNS queries look "generated" rather
than typed by a human, or whose DNS traffic pattern looks
more like smuggled data than normal browsing lookups.

Only DNS query NAMES and counts are used -- DNS names are
always sent in the clear, so this is metadata, not
decrypted payload.
"""

from typing import Dict

from detectors.detection_result import DetectionResult


MIN_QUERY_COUNT = 5
MIN_HIGH_ENTROPY_RATIO = 0.5
MIN_UNIQUE_DOMAINS = 5
MIN_MEAN_LENGTH = 35  # real, typed domain names are rarely this long
MIN_QUERIES_PER_SECOND = 2.0


def detect_dga_dns(features: Dict) -> DetectionResult:

    reasons = []
    score = 0

    query_count = features.get("dns_query_count", 0)

    if query_count < MIN_QUERY_COUNT:
        # Not enough queries yet to judge this source fairly.
        return DetectionResult(
            detected=False,
            attack_type=None,
            severity="NONE",
            score=0,
            confidence=0.0,
            reasons=[],
        )

    high_entropy_ratio = features.get(
        "dns_high_entropy_ratio", 0.0
    )

    unique_domains = features.get(
        "dns_unique_domains", 0
    )

    mean_length = features.get(
        "dns_mean_length", 0.0
    )

    queries_per_second = features.get(
        "dns_queries_per_second", 0.0
    )

    # -----------------------------------------------------
    # Rule 1: Many random-looking domain names
    # -----------------------------------------------------

    if high_entropy_ratio >= MIN_HIGH_ENTROPY_RATIO:

        score += 1

        reasons.append(
            f"many random-looking domain names "
            f"({high_entropy_ratio:.0%} of queries)"
        )

    # -----------------------------------------------------
    # Rule 2: Many different domains queried
    # -----------------------------------------------------

    if unique_domains >= MIN_UNIQUE_DOMAINS:

        score += 1

        reasons.append(
            f"many different domains queried "
            f"({unique_domains} unique domains)"
        )

    # -----------------------------------------------------
    # Rule 3: Unusually long domain names
    # (tunnelling encodes data INTO the name, making it long)
    # -----------------------------------------------------

    if mean_length >= MIN_MEAN_LENGTH:

        score += 1

        reasons.append(
            f"unusually long domain names "
            f"(average {mean_length:.0f} characters)"
        )

    # -----------------------------------------------------
    # Rule 4: High query rate
    # -----------------------------------------------------

    if queries_per_second >= MIN_QUERIES_PER_SECOND:

        score += 1

        reasons.append(
            f"high DNS query rate "
            f"({queries_per_second:.1f} queries/sec)"
        )

    detected = score >= 2

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
        attack_type="DGA_DNS_TUNNELLING" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
