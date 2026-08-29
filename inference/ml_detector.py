"""
CTD — ML Anomaly Detector

Loads the trained Isolation Forest model (see
train_model.py) and scores a source's combined feature
vector for overall anomalousness.

This plugs into the SAME pipeline as the 5 rule-based
detectors -- it takes a feature dict and returns a
DetectionResult, so DetectorEngine doesn't need to treat
it any differently.

============================================================
WHY THIS DETECTOR EXISTS ALONGSIDE THE RULE-BASED ONES
============================================================

The rule-based detectors are precise and explainable, but
each one only looks at a SMALL, SPECIFIC combination of
features (e.g. "SYN ratio AND packet rate"). This ML layer
instead looks at ALL features TOGETHER, and can catch a
source that is mildly unusual across MANY features at once
-- a pattern too spread-out for any single fixed rule to
catch, but that still doesn't look like "normal" behavior
overall.

HONEST LIMITATION (worth mentioning in your report):
Testing this model showed that a single WILDLY extreme
feature does not always get flagged strongly by itself,
if the other features in the same vector look typical --
this is a known characteristic of how Isolation Forest
randomly selects features to split on. This is exactly why
this ML layer complements, rather than replaces, the 5
rule-based detectors: the rules catch precise, known
single-feature/few-feature attack signatures reliably; the
ML layer adds a second, complementary pass looking for
broader, less-defined weirdness.
"""

import json
import os

from detectors.detection_result import DetectionResult
from inference.feature_schema import FEATURE_NAMES, features_to_vector


MODEL_PATH = os.path.join(
    os.path.dirname(__file__), "model.joblib"
)

STATS_PATH = os.path.join(
    os.path.dirname(__file__), "feature_stats.json"
)


# -----------------------------------------------------------
# Calibrated from real testing of the trained model (see
# project documentation). Isolation Forest's decision_function
# for genuinely anomalous points in this project typically
# lands somewhere between about -0.03 and -0.2.
# -----------------------------------------------------------

CONFIDENCE_SCALE = 0.20
MIN_CONFIDENCE_WHEN_DETECTED = 0.3


# Lazy-loaded singletons, so the model file is only read
# from disk once, the first time it's actually needed.
_model = None
_stats = None
_load_attempted = False
_warned_missing = False


def _try_load():

    global _model, _stats, _load_attempted, _warned_missing

    if _load_attempted:
        return

    _load_attempted = True

    if not (os.path.exists(MODEL_PATH) and os.path.exists(STATS_PATH)):

        if not _warned_missing:

            print(
                "[ML detector] No trained model found yet. "
                "Rule-based detectors will still run normally. "
                "To enable the ML layer, run:\n"
                "  python -m inference.train_model"
            )

            _warned_missing = True

        return

    import joblib

    _model = joblib.load(MODEL_PATH)

    with open(STATS_PATH) as f:
        _stats = json.load(f)


def _explain(vector, stats):
    """
    Turn the raw feature vector into a short list of
    human-readable "which features looked unusual" reasons,
    using the z-score (how many standard deviations away
    from the normal-training mean) of each feature.
    """

    deviations = []

    for name, value in zip(FEATURE_NAMES, vector):

        mean = stats[name]["mean"]
        std = stats[name]["std"]

        z_score = (value - mean) / std

        deviations.append((name, value, z_score))

    # Sort by how extreme the deviation is, largest first.
    deviations.sort(key=lambda item: abs(item[2]), reverse=True)

    reasons = []

    for name, value, z_score in deviations[:3]:

        if abs(z_score) < 1.5:
            # Not really unusual enough to mention.
            continue

        direction = "higher" if z_score > 0 else "lower"

        reasons.append(
            f"{name} unusually {direction} than normal "
            f"(value={value:.2f}, z-score={z_score:.1f})"
        )

    return reasons


def detect_ml_anomaly(features: dict) -> DetectionResult:

    _try_load()

    if _model is None:

        # Model not trained yet -- behave as "nothing
        # detected" rather than crashing the pipeline.
        return DetectionResult(
            detected=False,
            attack_type=None,
            severity="NONE",
            score=0,
            confidence=0.0,
            reasons=[],
        )

    vector = features_to_vector(features)

    prediction = _model.predict([vector])[0]
    raw_score = _model.decision_function([vector])[0]

    is_anomaly = prediction == -1

    if not is_anomaly:

        return DetectionResult(
            detected=False,
            attack_type=None,
            severity="NONE",
            score=0,
            confidence=0.0,
            reasons=[],
        )

    # Convert the raw score into a friendlier 0-1 confidence.
    # More negative raw_score = more anomalous.
    confidence = min(
        1.0,
        max(
            MIN_CONFIDENCE_WHEN_DETECTED,
            -raw_score / CONFIDENCE_SCALE,
        ),
    )

    if confidence >= 0.75:
        severity = "HIGH"
    elif confidence >= 0.5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    reasons = _explain(vector, _stats)

    if not reasons:
        reasons = [
            "overall behavior pattern is statistically unusual "
            "across multiple features combined"
        ]

    return DetectionResult(
        detected=True,
        attack_type="ML_ANOMALY",
        severity=severity,
        score=round(confidence * 4),
        confidence=confidence,
        reasons=reasons,
    )


if __name__ == "__main__":

    # Small self-test you can run directly:
    #   python -m inference.ml_detector

    print("=" * 60)
    print("CTD -- ML Detector Self-Test")
    print("=" * 60)

    normal_traffic = {
        "packets_per_second": 3.0,
        "bytes_per_second": 500.0,
        "syn_packet_ratio": 0.05,
        "unique_destinations": 2,
        "unique_destination_ports": 2,
        "active_flows": 2,
        "flows_per_second": 2.0,
        "outbound_inbound_ratio": 0.2,
    }

    print()
    print("NORMAL-LOOKING TRAFFIC:")
    result = detect_ml_anomaly(normal_traffic)
    print("  Detected:", result.detected)

    suspicious_traffic = {
        "packets_per_second": 400.0,
        "bytes_per_second": 900.0,
        "syn_packet_ratio": 0.95,
        "unique_destinations": 60,
        "unique_destination_ports": 60,
        "active_flows": 60,
        "flows_per_second": 60.0,
        "outbound_inbound_ratio": 5.0,
    }

    print()
    print("SUSPICIOUS-LOOKING TRAFFIC:")
    result = detect_ml_anomaly(suspicious_traffic)
    print("  Detected:", result.detected)
    print("  Severity:", result.severity)
    print("  Confidence:", round(result.confidence, 2))
    print("  Reasons:")
    for reason in result.reasons:
        print("   -", reason)
