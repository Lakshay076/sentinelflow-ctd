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
from typing import Dict, List

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
ANOMALY_SCORE_THRESHOLD = -0.04


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

    try:
        import joblib

        _model = joblib.load(MODEL_PATH)

        with open(STATS_PATH) as f:
            _stats = json.load(f)
    except Exception as e:
        if not _warned_missing:
            print(
                f"[ML detector] Could not load model ({e}). "
                "Rule-based detectors will still run normally."
            )
            _warned_missing = True


def _explain(vector, stats):
    """
    Turn the raw feature vector into a short list of
    human-readable reasons.

    For stable baseline features, use z-score to measure
    how unusual the value is. For near-constant baseline
    features, avoid meaningless enormous z-scores and
    report the observed value relative to the benign
    baseline instead.
    """

    deviations = []

    # A standard deviation below this value means the
    # benign training data was effectively constant for
    # that feature. In that case, a z-score would be
    # numerically huge but not useful to an analyst.
    STD_EPSILON = 1e-4

    for name, value in zip(FEATURE_NAMES, vector):

        mean = stats[name]["mean"]
        std = stats[name]["std"]

        if std < STD_EPSILON:
            # Preserve the direction and magnitude of the
            # deviation without producing misleading z-scores.
            deviation = abs(value - mean)

            if deviation > 0:
                deviations.append(
                    (name, value, None, mean, deviation)
                )
        else:
            z_score = (value - mean) / std
            deviations.append(
                (name, value, z_score, mean, abs(value - mean))
            )

    # Sort stable z-score features by z-score magnitude.
    # Near-constant features are sorted by absolute deviation.
    deviations.sort(
        key=lambda item: (
            abs(item[2]) if item[2] is not None
            else item[4]
        ),
        reverse=True,
    )

    reasons = []

    for name, value, z_score, mean, deviation in deviations[:3]:

        if z_score is not None:

            if abs(z_score) < 1.5:
                continue

            direction = "higher" if z_score > 0 else "lower"

            reasons.append(
                f"{name} unusually {direction} than normal "
                f"(value={value:.2f}, z-score={z_score:.1f})"
            )

        else:
            # Near-constant baseline: explain the actual
            # deviation instead of exposing an enormous
            # meaningless z-score.
            direction = "higher" if value > mean else "lower"

            reasons.append(
                f"{name} deviates strongly from normal baseline "
                f"(value={value:.2f}, baseline={mean:.2f})"
            )

    return reasons


def _no_anomaly_result() -> DetectionResult:
    return DetectionResult(
        detected=False,
        attack_type=None,
        severity="NONE",
        score=0,
        confidence=0.0,
        reasons=[],
    )


def _ml_feature_view(features: dict) -> dict:
    """
    Build the same-window feature view expected by IsolationForest.

    SourceAggregator scopes ``unique_destinations`` to initiated connections
    (TCP SYN and UDP) so scan heuristics never count established TCP ACKs.
    When an active sender in the current 1-second window has non-SYN outbound
    packets (``observed_unique_destinations > 0``) and ``unique_destinations == 0``,
    map the same-window observed destination counts so ML does not treat normal
    established TCP flows as contacting zero destinations.
    """
    obs_dests = features.get("observed_unique_destinations")
    if obs_dests is not None and features.get("unique_destinations", 0) == 0 and obs_dests > 0:
        view = dict(features)
        view["unique_destinations"] = obs_dests
        if view.get("unique_destination_ports", 0) == 0:
            view["unique_destination_ports"] = features.get("observed_unique_destination_ports", 0)
        if view.get("ports_per_destination", 0.0) == 0.0:
            view["ports_per_destination"] = features.get("observed_ports_per_destination", 0.0)
        return view
    return features


def _is_active_for_ml(features: dict) -> bool:
    """Return True if the source shows enough activity to score with ML."""
    packets = features.get("packets", 0)
    bytes_sent = features.get("bytes", 0)
    flows = features.get("active_flows", 0)
    dns_count = features.get("dns_query_count", 0)
    tls_count = features.get("tls_client_hello_count", 0)
    return not (
        packets < 5
        and bytes_sent < 500
        and flows < 3
        and dns_count < 2
        and tls_count < 1
    )


def _score_to_detection(vector: list, raw_score: float) -> DetectionResult:
    """
    Convert an IsolationForest decision_function score into a DetectionResult.

    In scikit-learn IsolationForest, predict(X) == -1 iff decision_function(X) < 0.
    Since ANOMALY_SCORE_THRESHOLD (-0.04) < 0, checking raw_score < -0.04 is
    equivalent to (prediction == -1 and raw_score < -0.04) with a single tree pass.
    """
    if raw_score >= ANOMALY_SCORE_THRESHOLD:
        return _no_anomaly_result()

    # Convert the raw score into a friendlier 0-1 confidence.
    # More negative raw_score = more anomalous.
    confidence = float(min(
        1.0,
        max(
            MIN_CONFIDENCE_WHEN_DETECTED,
            -raw_score / CONFIDENCE_SCALE,
        ),
    ))

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
        score=int(round(confidence * 4)),
        confidence=confidence,
        reasons=reasons,
    )


def detect_ml_anomalies_batch(features_list: List[Dict]) -> List[DetectionResult]:
    """
    Score a batch of source feature dictionaries in a single IsolationForest
    decision_function() call while preserving exact per-source decision semantics.
    """
    if not features_list:
        return []

    _try_load()

    if _model is None:
        return [_no_anomaly_result() for _ in features_list]

    results = [_no_anomaly_result() for _ in features_list]
    active_indices = []
    active_vectors = []

    for idx, features in enumerate(features_list):
        if _is_active_for_ml(features):
            active_indices.append(idx)
            active_vectors.append(features_to_vector(_ml_feature_view(features)))

    if not active_vectors:
        return results

    raw_scores = _model.decision_function(active_vectors)
    for idx, vector, raw_score in zip(active_indices, active_vectors, raw_scores):
        results[idx] = _score_to_detection(vector, float(raw_score))

    return results


def detect_ml_anomaly(features: dict) -> DetectionResult:
    _try_load()

    if _model is None:
        # Model not trained yet -- behave as "nothing
        # detected" rather than crashing the pipeline.
        return _no_anomaly_result()

    if not _is_active_for_ml(features):
        return _no_anomaly_result()

    vector = features_to_vector(_ml_feature_view(features))
    raw_score = float(_model.decision_function([vector])[0])
    return _score_to_detection(vector, raw_score)


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
