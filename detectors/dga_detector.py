"""
CTD — Advanced DGA / DNS Tunnelling Detector

Detects malicious DNS activity:
1. Domain Generation Algorithms (DGA): Malware generating pseudo-random
   domain names to rendezvous with command-and-control (C2) servers.
2. DNS Tunnelling: Smuggling arbitrary data inside DNS queries/responses
   (e.g., base32/hex payloads in long subdomains or rapid TXT/NULL queries).

Signals evaluated:
- Shannon entropy of query names.
- Character n-gram transition anomaly scoring.
- Domain lexical anomaly (consonant runs, digit ratios).
- DNS query-type distribution (TXT query concentration).
- Maximum and mean label lengths (data encapsulation).
- Query velocity and domain diversity.
- Response size anomalies (where response metadata is captured).

Passive metadata inspection only:
- Zero payload decryption of encrypted DNS (DoH/DoT).
- Zero active DNS probing or transmission.
"""

from typing import Dict, Optional
from detectors.detection_result import DetectionResult


# ---------------------------------------------------------------------
# Configurable Thresholds (Defaults)
# ---------------------------------------------------------------------

MIN_QUERY_COUNT: int = 5
MIN_HIGH_ENTROPY_RATIO: float = 0.50
MIN_UNIQUE_DOMAINS: int = 5
MIN_MEAN_LENGTH: float = 35.0  # Real typed domains are rarely this long
MIN_QUERIES_PER_SECOND: float = 2.0

# Advanced N-gram & Lexical Thresholds
MIN_NGRAM_ANOMALY_RATIO: float = 0.40
MIN_MEAN_NGRAM_ANOMALY: float = 0.45
MIN_LEXICAL_ANOMALY_RATIO: float = 0.40
MIN_MEAN_LEXICAL_SCORE: float = 0.45

# DNS Tunnelling & Query-Type Thresholds
MIN_LONG_LABEL_RATIO: float = 0.30
MIN_MAX_LABEL_LENGTH: int = 30
MIN_TXT_QUERY_RATIO: float = 0.40
MIN_TXT_QUERY_COUNT: int = 5
MIN_RESPONSE_BYTES_ANOMALY: int = 512


def detect_dga_dns(
    features: Dict,
    thresholds: Optional[Dict] = None,
) -> DetectionResult:
    """
    Evaluate feature vector for DGA domains or DNS tunnelling activity.

    Parameters:
        features: Dictionary containing DNS features:
            - dns_query_count: int
            - dns_high_entropy_ratio: float
            - dns_unique_domains: int
            - dns_mean_length: float
            - dns_queries_per_second: float
            - dns_mean_ngram_anomaly: Optional[float]
            - dns_high_ngram_ratio: Optional[float]
            - dns_mean_lexical_score: Optional[float]
            - dns_lexical_anomaly_ratio: Optional[float]
            - dns_max_label_length: Optional[int]
            - dns_long_label_ratio: Optional[float]
            - dns_txt_query_count: Optional[int]
            - dns_txt_query_ratio: Optional[float]
            - dns_mean_response_bytes: Optional[float]
        thresholds: Optional dictionary overriding any default threshold.

    Returns:
        DetectionResult with detected, attack_type="DGA_DNS_TUNNELLING",
        severity, score, confidence, and reasons.
    """
    cfg = {
        "min_query_count": MIN_QUERY_COUNT,
        "min_high_entropy_ratio": MIN_HIGH_ENTROPY_RATIO,
        "min_unique_domains": MIN_UNIQUE_DOMAINS,
        "min_mean_length": MIN_MEAN_LENGTH,
        "min_queries_per_second": MIN_QUERIES_PER_SECOND,
        "min_ngram_anomaly_ratio": MIN_NGRAM_ANOMALY_RATIO,
        "min_mean_ngram_anomaly": MIN_MEAN_NGRAM_ANOMALY,
        "min_lexical_anomaly_ratio": MIN_LEXICAL_ANOMALY_RATIO,
        "min_mean_lexical_score": MIN_MEAN_LEXICAL_SCORE,
        "min_long_label_ratio": MIN_LONG_LABEL_RATIO,
        "min_max_label_length": MIN_MAX_LABEL_LENGTH,
        "min_txt_query_ratio": MIN_TXT_QUERY_RATIO,
        "min_txt_query_count": MIN_TXT_QUERY_COUNT,
        "min_response_bytes_anomaly": MIN_RESPONSE_BYTES_ANOMALY,
    }
    if thresholds:
        cfg.update(thresholds)

    query_count = features.get("dns_query_count", 0)
    if query_count < cfg["min_query_count"]:
        # Not enough queries yet to judge this source fairly.
        return DetectionResult(
            detected=False,
            attack_type=None,
            severity="NONE",
            score=0,
            confidence=0.0,
            reasons=[],
        )

    reasons = []
    score = 0

    high_entropy_ratio = features.get("dns_high_entropy_ratio", 0.0)
    unique_domains = features.get("dns_unique_domains", 0)
    mean_length = features.get("dns_mean_length", 0.0)
    queries_per_second = features.get("dns_queries_per_second", 0.0)

    # Advanced N-gram & Lexical features
    mean_ngram_anomaly = features.get("dns_mean_ngram_anomaly", 0.0)
    high_ngram_ratio = features.get("dns_high_ngram_ratio", 0.0)
    mean_lexical_score = features.get("dns_mean_lexical_score", 0.0)
    lexical_anomaly_ratio = features.get("dns_lexical_anomaly_ratio", 0.0)

    # Tunnelling Label & Query Type features
    max_label_length = features.get("dns_max_label_length", 0)
    long_label_ratio = features.get("dns_long_label_ratio", 0.0)
    txt_query_count = features.get("dns_txt_query_count", 0)
    txt_query_ratio = features.get("dns_txt_query_ratio", 0.0)
    mean_response_bytes = features.get("dns_mean_response_bytes", 0.0)

    # -----------------------------------------------------
    # Rule 1: High Shannon Entropy (Random-Looking Names)
    # -----------------------------------------------------
    if high_entropy_ratio >= cfg["min_high_entropy_ratio"]:
        score += 1
        reasons.append(
            f"many random-looking domain names ({high_entropy_ratio:.0%} of queries)"
        )

    # -----------------------------------------------------
    # Rule 2: High Domain Diversity (Many Unique Domains)
    # -----------------------------------------------------
    if unique_domains >= cfg["min_unique_domains"]:
        score += 1
        reasons.append(
            f"many different domains queried ({unique_domains} unique domains)"
        )

    # -----------------------------------------------------
    # Rule 3: Unusually Long Domain Names (Mean Length)
    # -----------------------------------------------------
    if mean_length >= cfg["min_mean_length"]:
        score += 1
        reasons.append(
            f"unusually long domain names (average {mean_length:.0f} characters)"
        )

    # -----------------------------------------------------
    # Rule 4: High Query Rate
    # -----------------------------------------------------
    if queries_per_second >= cfg["min_queries_per_second"]:
        score += 1
        reasons.append(
            f"high DNS query rate ({queries_per_second:.1f} queries/sec)"
        )

    # -----------------------------------------------------
    # Rule 5: Character N-Gram Anomaly (Linguistic Transition Irregularity)
    # -----------------------------------------------------
    if (
        high_ngram_ratio >= cfg["min_ngram_anomaly_ratio"]
        or mean_ngram_anomaly >= cfg["min_mean_ngram_anomaly"]
    ):
        score += 1
        reasons.append(
            f"abnormal character n-gram distribution ({high_ngram_ratio:.0%} unnatural transitions)"
        )

    # -----------------------------------------------------
    # Rule 6: Domain Lexical Anomaly (Consonant Runs, High Digit Ratios)
    # -----------------------------------------------------
    if (
        lexical_anomaly_ratio >= cfg["min_lexical_anomaly_ratio"]
        or mean_lexical_score >= cfg["min_mean_lexical_score"]
    ):
        score += 1
        reasons.append(
            f"elevated domain lexical anomaly ({lexical_anomaly_ratio:.0%} of queries with consonant runs or high digit ratios)"
        )

    # -----------------------------------------------------
    # Rule 7: Long DNS Labels (Tunnelling Encapsulation)
    # -----------------------------------------------------
    if (
        long_label_ratio >= cfg["min_long_label_ratio"]
        or max_label_length >= cfg["min_max_label_length"]
    ):
        score += 1
        reasons.append(
            f"suspiciously long DNS labels consistent with data encapsulation (max label {max_label_length} chars)"
        )

    # -----------------------------------------------------
    # Rule 8: Unusual TXT Query Frequency (Tunnelling / Exfiltration)
    # Note: TXT queries alone are NOT treated as malicious (e.g. SPF/DKIM).
    # Requires suspicious payload indicators (diversity, entropy, or long labels).
    # -----------------------------------------------------
    is_txt_heavy = (
        txt_query_ratio >= cfg["min_txt_query_ratio"]
        and txt_query_count >= cfg["min_txt_query_count"]
    )
    has_suspicious_payload = (
        unique_domains >= 4
        or high_entropy_ratio >= 0.35
        or long_label_ratio >= 0.25
        or high_ngram_ratio >= 0.35
        or mean_length >= 30.0
    )
    if is_txt_heavy and has_suspicious_payload:
        score += 1
        reasons.append(
            f"unusual TXT query volume combined with suspicious domain payloads "
            f"({txt_query_count} TXT queries, {txt_query_ratio:.0%} of queries)"
        )

    # -----------------------------------------------------
    # Rule 9: Oversized DNS Response Payloads (Where Captured)
    # -----------------------------------------------------
    if mean_response_bytes >= cfg["min_response_bytes_anomaly"]:
        score += 1
        reasons.append(
            f"oversized DNS response payloads (average {mean_response_bytes:.0f} bytes)"
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

    confidence = min(score / 4.0, 1.0) if detected else min(score / 4.0, 0.49)

    return DetectionResult(
        detected=detected,
        attack_type="DGA_DNS_TUNNELLING" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
