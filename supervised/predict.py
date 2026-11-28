"""
SentinelFlow-CTD — Supervised Classifier: Prediction
=====================================================

Turns a fitted model into threat-category predictions.

This module is the offline prediction path used to check a trained model.
It is not wired into the live detection pipeline (that is a later phase).

Low-confidence predictions become UNCLASSIFIED. That label is not a
training class. The original model prediction is still returned as
model_prediction so a low-confidence call can be inspected.
"""

from typing import Dict, List, Optional

import numpy as np

from supervised.label_mapping import DEFAULT_CONFIDENCE_THRESHOLD, UNKNOWN_CATEGORY
from supervised.preprocessing import transform


def classify_features(
    model,
    preprocessor,
    label_encoder,
    X,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    top_k: int = 3,
) -> List[Dict]:
    """
    Classify raw feature rows.

    Parameters
    ----------
    model, preprocessor, label_encoder :
        Artifacts from training. The preprocessor must already be fitted.
    X : array-like, shape (n_samples, n_features)
        Features in the same order as feature_names.json, before scaling.
    threshold : float
        Minimum top-class probability. Below this, the returned category
        is UNCLASSIFIED.
    top_k : int
        How many alternative categories to include, after the top class.

    Returns
    -------
    list of dicts, one per input row:
      predicted_threat, model_prediction, confidence,
      classification_status, alternative_predictions
    """
    X_arr = np.asarray(X, dtype=np.float64)
    if X_arr.ndim == 1:
        X_arr = X_arr.reshape(1, -1)

    X_ready = transform(preprocessor, X_arr)
    probabilities = model.predict_proba(X_ready)
    class_names = [str(c) for c in label_encoder.classes_]

    if probabilities.shape[1] != len(class_names):
        raise ValueError(
            "predict_proba columns do not match the label encoder. "
            f"Got {probabilities.shape[1]} columns and {len(class_names)} classes."
        )

    results = []
    for row in probabilities:
        order = np.argsort(row)[::-1]
        top_index = int(order[0])
        confidence = float(row[top_index])
        model_prediction = class_names[top_index]
        if confidence < threshold:
            predicted = UNKNOWN_CATEGORY
            status = "unclassified"
        else:
            predicted = model_prediction
            status = "classified"

        alternatives = []
        for index in order[1: 1 + top_k]:
            alternatives.append({
                "category": class_names[int(index)],
                "confidence": round(float(row[int(index)]), 6),
            })

        results.append({
            "predicted_threat": predicted,
            "model_prediction": model_prediction,
            "confidence": round(confidence, 6),
            "classification_status": status,
            "alternative_predictions": alternatives,
        })
    return results
