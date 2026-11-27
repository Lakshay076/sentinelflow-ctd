import json
import logging
import math
import os
import threading

import pandas as pd

from detectors.detection_result import DetectionResult
from inference.supervised_schema import (
    SUPERVISED_CLASSES,
    SUPERVISED_DEFAULT_VALUES,
    SUPERVISED_FEATURE_NAMES,
    supervised_features_to_vector,
)


MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "supervised_model.joblib",
)
METADATA_PATH = os.path.join(
    os.path.dirname(__file__),
    "supervised_metadata.json",
)
DEFAULT_CONFIDENCE_THRESHOLD = 0.75

_logger = logging.getLogger(__name__)
_model = None
_metadata = None
_load_attempted = False
_load_error = None
_load_lock = threading.Lock()
_warning_lock = threading.Lock()
_warned = set()

_HIGH_SEVERITY_ATTACKS = {
    "SYN_FLOOD",
    "PORT_SCAN",
    "C2_BEACONING",
    "DATA_EXFILTRATION",
}


def _warn_once(key, message):
    with _warning_lock:
        if key in _warned:
            return
        _warned.add(key)
    _logger.warning(message)


def _fallback():
    return DetectionResult(
        detected=False,
        attack_type="NONE",
        severity="LOW",
        score=0.0,
        confidence=0.0,
        reasons=[],
    )


def _load_artifacts():
    global _model, _metadata, _load_attempted, _load_error

    with _load_lock:
        if not _load_attempted:
            _load_attempted = True
            missing = [
                path
                for path in (MODEL_PATH, METADATA_PATH)
                if not os.path.isfile(path)
            ]
            if missing:
                _load_error = (
                    "Missing supervised detector artifact(s): "
                    + ", ".join(os.path.basename(path) for path in missing)
                )
            else:
                try:
                    import joblib

                    loaded_model = joblib.load(MODEL_PATH)
                    with open(METADATA_PATH, "r", encoding="utf-8") as file:
                        loaded_metadata = json.load(file)

                    if not callable(getattr(loaded_model, "predict_proba", None)):
                        raise ValueError(
                            "Loaded supervised model does not expose predict_proba()"
                        )
                    if getattr(loaded_model, "classes_", None) is None:
                        raise ValueError(
                            "Loaded supervised model does not expose classes_"
                        )
                    if not isinstance(loaded_metadata, dict):
                        raise ValueError(
                            "Supervised metadata must be a JSON object"
                        )

                    threshold_value = loaded_metadata.get(
                        "confidence_threshold",
                        DEFAULT_CONFIDENCE_THRESHOLD,
                    )
                    if isinstance(threshold_value, bool):
                        raise ValueError(
                            "confidence_threshold must be a finite number from 0 to 1"
                        )
                    threshold = float(threshold_value)
                    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
                        raise ValueError(
                            "confidence_threshold must be a finite number from 0 to 1"
                        )

                    classes = list(loaded_model.classes_)
                    if not classes:
                        raise ValueError("Loaded supervised model has no classes")
                    normalized_classes = []
                    for class_id in classes:
                        numeric_class_id = float(class_id)
                        if (
                            not math.isfinite(numeric_class_id)
                            or not numeric_class_id.is_integer()
                        ):
                            raise ValueError(
                                f"Invalid class ID in model.classes_: {class_id!r}"
                            )
                        normalized_class_id = int(numeric_class_id)
                        if normalized_class_id not in SUPERVISED_CLASSES:
                            raise ValueError(
                                f"Unknown class ID in model.classes_: {class_id!r}"
                            )
                        normalized_classes.append(normalized_class_id)
                    if len(set(normalized_classes)) != len(normalized_classes):
                        raise ValueError(
                            "Loaded supervised model contains duplicate class IDs"
                        )

                    n_features = getattr(loaded_model, "n_features_in_", None)
                    if (
                        n_features is not None
                        and int(n_features) != len(SUPERVISED_FEATURE_NAMES)
                    ):
                        raise ValueError(
                            f"Model expects {n_features} features; "
                            f"schema provides {len(SUPERVISED_FEATURE_NAMES)}"
                        )

                    loaded_metadata["confidence_threshold"] = threshold
                    _model = loaded_model
                    _metadata = loaded_metadata
                except Exception as error:
                    _load_error = (
                        f"Could not load supervised detector artifacts: {error}"
                    )

    if _load_error:
        _warn_once("artifact_load", _load_error)
    return _model, _metadata


def _feature_reasons(features):
    candidates = []
    for position, name in enumerate(SUPERVISED_FEATURE_NAMES):
        if name not in features:
            continue
        try:
            value = float(features[name])
        except (TypeError, ValueError):
            continue
        if not math.isfinite(value):
            continue

        default = float(SUPERVISED_DEFAULT_VALUES[name])
        if value == default:
            continue
        relative_change = abs(value - default) / max(abs(default), 1.0)
        candidates.append(
            (relative_change, -position, name, value, default)
        )

    candidates.sort(reverse=True)
    return [
        (
            f"[Supervised ML] Observed {name}={value:.4g} "
            f"(default={default:.4g})"
        )
        for _, _, name, value, default in candidates[:2]
    ]


def detect_supervised_threat(features: dict) -> DetectionResult:
    model, metadata = _load_artifacts()
    if model is None or metadata is None:
        return _fallback()

    if not isinstance(features, dict) or not features:
        _warn_once(
            "invalid_features",
            "[Supervised ML] Expected a non-empty feature dictionary; "
            "returning no detection.",
        )
        return _fallback()

    try:
        vector = supervised_features_to_vector(features)
        model_input = pd.DataFrame(
            [vector],
            columns=SUPERVISED_FEATURE_NAMES,
        )
        probability_rows = model.predict_proba(model_input)
        if len(probability_rows) != 1:
            raise ValueError("predict_proba() did not return one probability row")

        class_ids = [int(class_id) for class_id in model.classes_]
        probabilities = [float(value) for value in probability_rows[0]]
        if len(class_ids) != len(probabilities):
            raise ValueError(
                "predict_proba() output does not match model.classes_"
            )
        if any(
            not math.isfinite(probability) or not 0.0 <= probability <= 1.0
            for probability in probabilities
        ):
            raise ValueError("predict_proba() returned an invalid probability")

        top_index = max(
            range(len(probabilities)),
            key=probabilities.__getitem__,
        )
        class_id = class_ids[top_index]
        attack_type = SUPERVISED_CLASSES[class_id]
        confidence = probabilities[top_index]
        threshold = metadata["confidence_threshold"]
    except Exception as error:
        _warn_once(
            "prediction_failure",
            f"[Supervised ML] Could not score features safely: {error}",
        )
        return _fallback()

    reasons = [
        (
            f"[Supervised ML] Predicted {attack_type} with confidence "
            f"{confidence:.2f} (threshold={threshold:.2f})"
        )
    ]
    reasons.extend(_feature_reasons(features))

    detected = class_id != 0 and confidence >= threshold
    if not detected:
        return DetectionResult(
            detected=False,
            attack_type="NONE",
            severity="LOW",
            score=round(confidence * 100.0, 2),
            confidence=confidence,
            reasons=reasons,
        )

    if attack_type in _HIGH_SEVERITY_ATTACKS:
        severity = "CRITICAL" if confidence >= 0.95 else "HIGH"
    else:
        severity = "MEDIUM"

    return DetectionResult(
        detected=True,
        attack_type=attack_type,
        severity=severity,
        score=round(confidence * 100.0, 2),
        confidence=confidence,
        reasons=reasons,
    )
