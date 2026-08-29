"""
CTD — Data Exfiltration Detector

Detects large, one-sided outbound data transfers using
aggregated network metadata only.

No packet payloads are inspected -- this looks purely at
byte COUNTS and DIRECTION, never at the actual content
being sent.

Simple idea:
    Normal devices mostly RECEIVE more than they SEND
    (loading web pages, streaming video, etc).

    A device secretly leaking data does the opposite --
    it SENDS much more than it RECEIVES, often steadily,
    over a sustained period.
"""

from typing import Dict

from detectors.detection_result import DetectionResult


# -----------------------------------------------------------
# Thresholds
#
# These are intentionally simple, readable numbers so they
# are easy to explain in a demo or report. They can be tuned
# later once you have real/replayed traffic to test against.
# -----------------------------------------------------------

# Minimum bytes sent in the rolling window before we even
# consider this "large enough" to matter. Prevents flagging
# tiny, harmless bursts.
MIN_OUTBOUND_BYTES = 500_000  # 500 KB in the 10-second window

# Minimum ratio of (bytes sent) to (bytes received).
# A ratio of 5.0 means "sent 5x more than it received".
MIN_RATIO = 5.0

# Minimum number of packets, so a single oversized packet
# doesn't trigger a false alert.
MIN_PACKETS = 20


def detect_exfiltration(features: Dict) -> DetectionResult:

    reasons = []
    score = 0

    bytes_sent = features.get("bytes", 0)
    bytes_received = features.get("bytes_received", 0)

    outbound_inbound_ratio = features.get(
        "outbound_inbound_ratio", 0.0
    )

    packets = features.get("packets", 0)

    bytes_per_second = features.get(
        "bytes_per_second", 0.0
    )

    # -----------------------------------------------------
    # Rule 1: Large total outbound volume
    # -----------------------------------------------------

    if bytes_sent >= MIN_OUTBOUND_BYTES:

        score += 1

        reasons.append(
            f"large outbound volume "
            f"({bytes_sent} bytes sent in window)"
        )

    # -----------------------------------------------------
    # Rule 2: Highly asymmetric direction (sent >> received)
    # -----------------------------------------------------

    if outbound_inbound_ratio >= MIN_RATIO:

        score += 1

        reasons.append(
            f"asymmetric traffic direction "
            f"(sent {outbound_inbound_ratio:.1f}x more "
            f"than received)"
        )

    # -----------------------------------------------------
    # Rule 3: Enough packets to be a real, sustained
    # transfer (not just one big packet by accident)
    # -----------------------------------------------------

    if packets >= MIN_PACKETS:

        score += 1

        reasons.append(
            f"sustained transfer "
            f"({packets} packets in window)"
        )

    # -----------------------------------------------------
    # Rule 4: High sustained transfer rate
    # -----------------------------------------------------

    if bytes_per_second >= (MIN_OUTBOUND_BYTES / 10):

        score += 1

        reasons.append(
            f"high sustained transfer rate "
            f"({bytes_per_second:.0f} bytes/sec)"
        )

    # -----------------------------------------------------
    # Final decision
    #
    # We require the two most important signals --
    # large volume AND asymmetry -- to both be present,
    # not just any 2 of the 4 signals. This avoids flagging
    # e.g. a legitimate large but two-way file transfer.
    # -----------------------------------------------------

    large_volume = bytes_sent >= MIN_OUTBOUND_BYTES
    asymmetric = outbound_inbound_ratio >= MIN_RATIO

    detected = large_volume and asymmetric and score >= 3

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
        attack_type="DATA_EXFILTRATION" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
