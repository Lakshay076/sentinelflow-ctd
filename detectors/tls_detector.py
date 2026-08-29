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


# Real browsers (Chrome, Firefox, Edge, Safari) typically
# offer well over a dozen cipher suites and several
# extensions. A ClientHello offering far fewer than this
# often comes from a minimal/custom TLS library rather than
# a full browser.
MIN_CIPHER_COUNT_SUSPICIOUS = 5
MIN_EXTENSION_COUNT_SUSPICIOUS = 4

MIN_MISSING_SNI_RATIO = 0.5

MIN_REPEATED_IDENTICAL_HELLOS = 5


def detect_tls_anomaly(features: Dict) -> DetectionResult:

    reasons = []
    score = 0

    hello_count = features.get("tls_client_hello_count", 0)

    if hello_count == 0:
        return DetectionResult(
            detected=False,
            attack_type=None,
            severity="NONE",
            score=0,
            confidence=0.0,
            reasons=[],
        )

    avg_cipher_count = features.get(
        "tls_avg_cipher_count", 999
    )

    avg_extension_count = features.get(
        "tls_avg_extension_count", 999
    )

    missing_sni_ratio = features.get(
        "tls_missing_sni_ratio", 0.0
    )

    max_same_ja3_to_one_dest = features.get(
        "tls_max_same_ja3_to_one_dest", 0
    )

    # -----------------------------------------------------
    # Rule 1: Unusually few cipher suites offered
    # -----------------------------------------------------

    if avg_cipher_count <= MIN_CIPHER_COUNT_SUSPICIOUS:

        score += 1

        reasons.append(
            f"unusually few cipher suites offered "
            f"(avg {avg_cipher_count:.0f}, browsers typically "
            f"offer 15+)"
        )

    # -----------------------------------------------------
    # Rule 2: Unusually few extensions offered
    # -----------------------------------------------------

    if avg_extension_count <= MIN_EXTENSION_COUNT_SUSPICIOUS:

        score += 1

        reasons.append(
            f"unusually few TLS extensions offered "
            f"(avg {avg_extension_count:.0f})"
        )

    # -----------------------------------------------------
    # Rule 3: Missing server name (SNI)
    # -----------------------------------------------------

    if missing_sni_ratio >= MIN_MISSING_SNI_RATIO:

        score += 1

        reasons.append(
            f"server name (SNI) missing in "
            f"{missing_sni_ratio:.0%} of connections"
        )

    # -----------------------------------------------------
    # Rule 4: Same fingerprint repeated to same destination
    # -----------------------------------------------------

    if max_same_ja3_to_one_dest >= MIN_REPEATED_IDENTICAL_HELLOS:

        score += 1

        reasons.append(
            f"identical TLS fingerprint repeated to the same "
            f"destination {max_same_ja3_to_one_dest} times"
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
        attack_type="TLS_METADATA_ANOMALY" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
