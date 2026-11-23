"""
CTD — Encrypted-Session Metadata Anomaly Detector

Flags TLS clients whose ClientHello "shape" looks unlike a
normal browser -- far fewer cipher suites/extensions than
real browsers typically offer, a missing server name (SNI),
or the exact same fingerprint repeating to the same
destination many times (consistent with an automated
library making repeated connections, rather than everyday
human browsing).

No decrypted content is used anywhere. Only ClientHello
METADATA (counts, presence/absence of fields, and
repetition) is used.

HONESTY NOTE FOR YOUR REPORT/DOCS:
A production system would normally also check the JA3 hash
against a threat-intelligence blocklist of known-malicious
fingerprints. Building/maintaining such a blocklist is
outside the scope of a self-contained student prototype, so
this detector instead looks at STRUCTURAL anomalies in the
ClientHello itself -- a reasonable, explainable, and honest
substitute for a first working version.
"""

from typing import Dict

from detectors.detection_result import DetectionResult


"""
CTD — Encrypted-Session Metadata Anomaly Detector (TLS, JA3/JA4, QUIC, SPLT)

Flags TLS/QUIC clients whose session metadata looks unlike a normal browser:
- Structural ClientHello anomalies (few cipher suites, few extensions, missing SNI).
- Repeated identical JA3 or standards-compliant JA4 fingerprints to the same target.
- Robotic encrypted traffic timing sequences (low SPLT inter-packet arrival jitter).
- Uniform encrypted packet length sequences (fixed-block tunnelling / exfiltration).

No decrypted content is used anywhere. Only metadata (counts, presence/absence of fields,
fingerprint hashes, and packet size/timing sequences) is evaluated.
"""

from typing import Dict, Optional
from detectors.detection_result import DetectionResult


# ---------------------------------------------------------------------
# Configurable Thresholds (Defaults)
# ---------------------------------------------------------------------

MIN_CIPHER_COUNT_SUSPICIOUS: int = 5
MIN_EXTENSION_COUNT_SUSPICIOUS: int = 4
MIN_MISSING_SNI_RATIO: float = 0.50
MIN_REPEATED_IDENTICAL_HELLOS: int = 5
MIN_REPEATED_JA4: int = 5

# SPLT & Behavioral Sequence Thresholds
MIN_SPLT_TIMING_CV_SUSPICIOUS: float = 0.15      # Robotic / automated inter-packet arrival jitter
MIN_SPLT_LENGTH_STDEV_SUSPICIOUS: float = 10.0   # Fixed-size encrypted chunking / tunnelling


def detect_tls_anomaly(
    features: Dict,
    thresholds: Optional[Dict] = None,
) -> DetectionResult:
    """
    Evaluate feature vector for TLS, JA4, QUIC, or SPLT sequence anomalies.

    Parameters:
        features: Dictionary containing TLS/QUIC/SPLT features:
            - tls_client_hello_count: int
            - tls_avg_cipher_count: float
            - tls_avg_extension_count: float
            - tls_missing_sni_ratio: float
            - tls_max_same_ja3_to_one_dest: int
            - tls_max_same_ja4_to_one_dest: Optional[int]
            - splt_packet_count: Optional[int]
            - splt_mean_length: Optional[float]
            - splt_length_stdev: Optional[float]
            - splt_ipt_cv: Optional[float]
        thresholds: Optional dictionary overriding any default threshold.

    Returns:
        DetectionResult with detected, attack_type="TLS_METADATA_ANOMALY",
        severity, score, confidence, and reasons.
    """
    cfg = {
        "min_cipher_count_suspicious": MIN_CIPHER_COUNT_SUSPICIOUS,
        "min_extension_count_suspicious": MIN_EXTENSION_COUNT_SUSPICIOUS,
        "min_missing_sni_ratio": MIN_MISSING_SNI_RATIO,
        "min_repeated_identical_hellos": MIN_REPEATED_IDENTICAL_HELLOS,
        "min_repeated_ja4": MIN_REPEATED_JA4,
        "min_splt_timing_cv_suspicious": MIN_SPLT_TIMING_CV_SUSPICIOUS,
        "min_splt_length_stdev_suspicious": MIN_SPLT_LENGTH_STDEV_SUSPICIOUS,
    }
    if thresholds:
        cfg.update(thresholds)

    hello_count = features.get("tls_client_hello_count", 0)
    quic_count = features.get("quic_packet_count", 0)
    splt_count = features.get("splt_packet_count", 0)

    if hello_count == 0 and quic_count == 0 and splt_count == 0:
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

    avg_cipher_count = features.get("tls_avg_cipher_count", 999.0)
    avg_extension_count = features.get("tls_avg_extension_count", 999.0)
    missing_sni_ratio = features.get("tls_missing_sni_ratio", 0.0)
    max_same_ja3 = features.get("tls_max_same_ja3_to_one_dest", 0)
    max_same_ja4 = features.get("tls_max_same_ja4_to_one_dest", 0)

    # SPLT features
    splt_mean_length = features.get("splt_mean_length", 0.0)
    splt_length_stdev = features.get("splt_length_stdev", 999.0)
    splt_ipt_cv = features.get("splt_ipt_cv", 1.0)

    # -----------------------------------------------------
    # Rule 1: Unusually few cipher suites offered
    # -----------------------------------------------------
    if hello_count > 0 and avg_cipher_count <= cfg["min_cipher_count_suspicious"]:
        score += 1
        reasons.append(
            f"unusually few cipher suites offered (avg {avg_cipher_count:.0f}, browsers typically offer 15+)"
        )

    # -----------------------------------------------------
    # Rule 2: Unusually few extensions offered
    # -----------------------------------------------------
    if hello_count > 0 and avg_extension_count <= cfg["min_extension_count_suspicious"]:
        score += 1
        reasons.append(
            f"unusually few TLS extensions offered (avg {avg_extension_count:.0f})"
        )

    # -----------------------------------------------------
    # Rule 3: Missing server name (SNI)
    # -----------------------------------------------------
    if hello_count > 0 and missing_sni_ratio >= cfg["min_missing_sni_ratio"]:
        score += 1
        reasons.append(
            f"server name (SNI) missing in {missing_sni_ratio:.0%} of connections"
        )

    # -----------------------------------------------------
    # Rule 4: Repeated identical JA3 / JA4 fingerprint
    # -----------------------------------------------------
    if max_same_ja3 >= cfg["min_repeated_identical_hellos"] or max_same_ja4 >= cfg["min_repeated_ja4"]:
        score += 1
        repeat_count = max(max_same_ja3, max_same_ja4)
        reasons.append(
            f"identical TLS/JA4 fingerprint repeated to the same destination {repeat_count} times"
        )

    # -----------------------------------------------------
    # Rule 5: Robotic SPLT Timing Sequence (Automated C2)
    # -----------------------------------------------------
    if splt_count >= 5 and splt_ipt_cv <= cfg["min_splt_timing_cv_suspicious"]:
        score += 1
        reasons.append(
            f"robotic encrypted traffic timing sequence (inter-packet timing CV {splt_ipt_cv:.2f} <= {cfg['min_splt_timing_cv_suspicious']:.2f})"
        )

    # -----------------------------------------------------
    # Rule 6: Uniform Encrypted Packet Lengths (Tunnelling)
    # -----------------------------------------------------
    if splt_count >= 8 and splt_mean_length >= 300.0 and splt_length_stdev <= cfg["min_splt_length_stdev_suspicious"]:
        score += 1
        reasons.append(
            f"uniform encrypted packet length sequence consistent with automated tunnelling (length stdev {splt_length_stdev:.1f} bytes)"
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
        attack_type="TLS_METADATA_ANOMALY" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
