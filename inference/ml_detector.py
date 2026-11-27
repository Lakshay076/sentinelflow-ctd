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
import math

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

# Minimum source activity required before the Isolation Forest is evaluated.
# These thresholds prevent a lone packet, lone flow, or lone DNS query from
# being sent through the model merely as "data present."
MIN_PACKETS_PER_SECOND = 5.0
MIN_BYTES_PER_SECOND = 500.0
MIN_ACTIVE_FLOWS = 3
MIN_FLOWS_PER_SECOND = 3.0
MIN_DNS_QUERIES = 2
MIN_TLS_CLIENT_HELLOS = 1


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

    model_available = os.path.exists(MODEL_PATH)
    stats_available = os.path.exists(STATS_PATH)
    if not model_available or not stats_available:
        if not _warned_missing:
            missing = []
            if not model_available:
                missing.append("model.joblib")
            if not stats_available:
                missing.append("feature_stats.json")
            print(
                "[ML detector] Missing artifact(s): "
                + ", ".join(missing)
                + ". Rule-based detectors will still run normally."
            )
            _warned_missing = True
        return

    temp_model = None
    temp_stats = None
    try:
        import joblib

        temp_model = joblib.load(MODEL_PATH)

        with open(STATS_PATH, "r", encoding="utf-8") as f:
            temp_stats = json.load(f)

        if not callable(getattr(temp_model, "predict", None)):
            raise ValueError("Loaded model does not expose predict()")
        if not callable(getattr(temp_model, "decision_function", None)):
            raise ValueError("Loaded model does not expose decision_function()")

        n_features = getattr(temp_model, "n_features_in_", None)
        if n_features is not None and int(n_features) != len(FEATURE_NAMES):
            raise ValueError(
                f"Model expects {n_features} features; "
                f"pipeline provides {len(FEATURE_NAMES)}"
            )

        if not isinstance(temp_stats, dict):
            raise ValueError("Feature statistics must be a JSON object")
        for name in FEATURE_NAMES:
            entry = temp_stats.get(name)
            if not isinstance(entry, dict):
                raise ValueError(f"Missing feature statistics for {name}")
            mean = entry.get("mean")
            std = entry.get("std")
            if isinstance(mean, bool) or isinstance(std, bool):
                raise ValueError(f"Invalid feature statistics for {name}")
            try:
                mean = float(mean)
                std = float(std)
            except (TypeError, ValueError):
                raise ValueError(f"Invalid feature statistics for {name}")
            if (
                not math.isfinite(mean)
                or not math.isfinite(std)
                or std < 0
            ):
                raise ValueError(f"Invalid feature statistics for {name}")

        # Commit only after both artifacts and their compatibility
        # checks have passed.
        _model = temp_model
        _stats = temp_stats
    except Exception as e:
        # Leave both detector artifacts unavailable so rule-based
        # detectors remain the only active ML-independent path.
        _model = None
        _stats = None
        if not _warned_missing:
            print(
                f"[ML detector] Could not load model artifacts ({e}). "
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

    stable_deviations = []
    near_constant_deviations = []
    STD_EPSILON = 1e-4

    for name, value in zip(FEATURE_NAMES, vector):
        mean = stats[name]["mean"]
        std = stats[name]["std"]
        value = float(value)
        mean = float(mean)
        std = float(std)

        if std < STD_EPSILON:
            if value != mean:
                near_constant_deviations.append((name, value, mean))
        else:
            z_score = (value - mean) / std
            stable_deviations.append((name, value, z_score, mean))

    stable_deviations.sort(key=lambda item: abs(item[2]), reverse=True)

    reasons = []

    # Stable features are ranked by standardized deviation. Near-constant
    # features are deliberately kept in a separate list and are reported
    # afterward in schema order; their raw units are not ranked against
    # standardized scores or against other near-constant features.
    for name, value, z_score, mean in stable_deviations:
        if abs(z_score) >= 1.5:
            direction = "higher" if z_score > 0 else "lower"
            reasons.append(
                f"{name} unusually {direction} than normal "
                f"(value={value:.2f}, z-score={z_score:.1f})"
            )
            if len(reasons) == 3:
                return reasons

    for name, value, mean in near_constant_deviations:
        direction = "higher" if value > mean else "lower"
        reasons.append(
            f"{name} deviates from near-constant baseline "
            f"(value={value:.2f}, baseline={mean:.2f}; direction={direction})"
        )
        if len(reasons) == 3:
            break

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

    # Ensure source has performed active traffic before evaluating ML anomaly
    # Idle or trivial background traffic (e.g. 1-2 packets) is not an anomaly
    def _guard_number(key, default=0):
        value = features.get(key, default)
        try:
            number = float(value)
        except (TypeError, ValueError):
            return float(default)
        return number if math.isfinite(number) else float(default)

    packets_per_second = _guard_number("packets_per_second")
    bytes_per_second = _guard_number("bytes_per_second")
    flows_per_second = _guard_number("flows_per_second")
    active_flows = _guard_number("active_flows")
    dns_count = _guard_number("dns_query_count")
    tls_count = _guard_number("tls_client_hello_count")

    # Missing values remain 0 for this guard only. They are separately
    # replaced by schema defaults before model evaluation.
    # An idle guard threshold is intentionally OR'ed across every meaningful
    # activity signal: a lone packet, flow, or DNS query must not bypass it.
    if (
        packets_per_second < MIN_PACKETS_PER_SECOND
        and bytes_per_second < MIN_BYTES_PER_SECOND
        and flows_per_second < MIN_FLOWS_PER_SECOND
        and active_flows < MIN_ACTIVE_FLOWS
        and dns_count < MIN_DNS_QUERIES
        and tls_count < MIN_TLS_CLIENT_HELLOS
    ):
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

    # Only flag as anomaly if the IsolationForest predicts -1 and score is meaningfully negative
    is_anomaly = (prediction == -1) and (raw_score < -0.04)

    if not is_anomaly:

        return DetectionResult(
            detected=False,
            attack_type=None,
            severity="NONE",
            score=0,
            confidence=0.0,
            reasons=[],
        )

    # Heuristic 0-1 anomaly-confidence display scale. This is not a
    # calibrated probability and should not be interpreted as P(attack).
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
        "rst_packet_ratio": 0.0,
        "unique_destinations": 2,
        "unique_destination_ports": 2,
        "active_flows": 2,
        "flows_per_second": 2.0,
        "ports_per_destination": 1.0,
        "bytes_received": 2500.0,
        "outbound_inbound_ratio": 0.2,
        "beacon_interval_cv": 1.0,
        "dns_high_entropy_ratio": 0.0,
        "dns_queries_per_second": 0.0,
        "tls_avg_cipher_count": 20.0,
        "tls_missing_sni_ratio": 0.0,
    }

    print()
    print("NORMAL-LOOKING TRAFFIC:")
    result = detect_ml_anomaly(normal_traffic)
    print("  Detected:", result.detected)

    suspicious_traffic = {
        "packets_per_second": 400.0,
        "bytes_per_second": 900.0,
        "syn_packet_ratio": 0.95,
        "rst_packet_ratio": 0.0,
        "unique_destinations": 60,
        "unique_destination_ports": 60,
        "active_flows": 60,
        "flows_per_second": 60.0,
        "ports_per_destination": 1.0,
        "bytes_received": 900.0,
        "outbound_inbound_ratio": 5.0,
        "beacon_interval_cv": 0.01,
        "dns_high_entropy_ratio": 0.95,
        "dns_queries_per_second": 20.0,
        "tls_avg_cipher_count": 2.0,
        "tls_missing_sni_ratio": 1.0,
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
