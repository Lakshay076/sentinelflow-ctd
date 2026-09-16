"""
CTD — Botnet C2 Beaconing Detector

Detects devices that repeatedly connect to the SAME
destination at suspiciously REGULAR time intervals --
a hallmark of malware "checking in" with a command-and-
control (C2) server.

Normal, human-driven traffic is irregular: you browse,
pause, get distracted, close a tab. A script/robot is not
-- it checks in like clockwork.

No packet payloads are inspected. Only connection TIMING
(when connections started) is used.
"""

from typing import Dict

from detectors.detection_result import DetectionResult


# Minimum number of repeated connections to the same
# destination before timing statistics are meaningful.
MIN_CONNECTIONS = 4

# Coefficient of variation = (standard deviation / mean).
# A LOW value means the timing is very regular/robotic.
# Real human/app traffic usually has a much higher value.
MAX_INTERVAL_CV = 0.25

# If a source is repeatedly contacting many different
# destinations, that looks more like scanning/fan-out than
# focused beaconing to one C2 server.
MAX_REPEATED_DESTINATIONS = 3

# Beaconing should represent periodic check-ins, not
# high-rate packet/flow bursts such as floods or transfers.
MIN_MEAN_INTERVAL = 1.0


def detect_c2_beaconing(features: Dict) -> DetectionResult:

    reasons = []
    score = 0

    connection_count = features.get(
        "beacon_connection_count", 0
    )

    interval_cv = features.get(
        "beacon_interval_cv", 1.0
    )

    mean_interval = features.get(
        "beacon_mean_interval", 0.0
    )

    repeated_destinations = features.get(
        "beacon_repeated_destinations", 0
    )

    # -----------------------------------------------------
    # Rule 1: Enough repeated connections to judge fairly
    # -----------------------------------------------------

    if connection_count >= MIN_CONNECTIONS:

        score += 1

        reasons.append(
            f"repeated connections to the same destination "
            f"({connection_count} times)"
        )

    # -----------------------------------------------------
    # Rule 2: Very regular timing (low variation)
    # -----------------------------------------------------

    if interval_cv <= MAX_INTERVAL_CV:

        score += 1

        reasons.append(
            f"highly regular check-in timing "
            f"(variation={interval_cv:.2f}, "
            f"avg interval={mean_interval:.1f}s)"
        )

    # -----------------------------------------------------
    # Rule 3: Meaningful check-in interval
    # -----------------------------------------------------

    if mean_interval >= MIN_MEAN_INTERVAL:

        score += 1

        reasons.append(
            f"meaningful check-in interval "
            f"(average={mean_interval:.1f}s)"
        )

    # -----------------------------------------------------
    # Rule 4: Focused on a small set of destinations,
    # not spread across many (that would look more like
    # scanning than beaconing).
    # -----------------------------------------------------

    if 0 < repeated_destinations <= MAX_REPEATED_DESTINATIONS:

        score += 1

        reasons.append(
            f"focused on a small set of destinations "
            f"({repeated_destinations} repeated destination(s))"
        )

    # -----------------------------------------------------
    # Final decision
    #
    # Regularity is the single most important signal for
    # beaconing, so we require it, plus at least one more
    # supporting signal.
    # -----------------------------------------------------

    regular_timing = interval_cv <= MAX_INTERVAL_CV
    enough_connections = connection_count >= MIN_CONNECTIONS
    meaningful_interval = mean_interval >= MIN_MEAN_INTERVAL

    detected = (
        regular_timing
        and enough_connections
        and meaningful_interval
        and score >= 3
    )

    if not detected:
        severity = "NONE"
    elif score >= 3:
        severity = "HIGH"
    elif score >= 2:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    confidence = min(score / 4.0, 1.0)

    return DetectionResult(
        detected=detected,
        attack_type="C2_BEACONING" if detected else None,
        severity=severity,
        score=score,
        confidence=confidence,
        reasons=reasons,
    )
