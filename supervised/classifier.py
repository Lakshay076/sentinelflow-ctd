"""
SentinelFlow-CTD — Supervised Threat Classifier Runtime Engine
==============================================================

Provides safe, high-performance runtime inference for classifying network
threats using the trained CIC-IDS2017 supervised Random Forest model.

Key Design & Safety Properties:
-------------------------------
1. Resilient & Non-Blocking:
   - Missing model files, corrupted artifacts, or schema mismatches will
     NEVER crash the detection pipeline or suppress an alert.
   - If inference fails, it logs a warning and returns status="ERROR" or
     status="MODEL_UNAVAILABLE". The alert itself is preserved 100%.

2. Confidence Thresholding & Fallback:
   - Evaluates probability confidence for all 8 threat categories.
   - Predictions with confidence < threshold (default 0.50) are safely
     marked as "UNCLASSIFIED" (or "UNKNOWN"), preserving anomaly detection
     for novel / zero-day threats.

3. Flow-Level Granularity (Not Packet-Level):
   - Evaluates candidate bidirectional flows associated with anomalous
     sources, maintaining high live-packet throughput.

4. Supporting Feature Attribution:
   - Extracts top contributing feature values for the predicted class
     to provide transparent explainability for security operators.
"""

import json
import logging
import os
from typing import Dict, List, Optional, Tuple, Union
import numpy as np

from supervised.feature_extractor import (
    FEATURE_SCHEMA_VERSION,
    FLOW_FEATURE_NAMES,
    FlowFeatureAccumulator,
)
from supervised.label_mapping import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    UNKNOWN_CATEGORY,
    ORDERED_CATEGORIES,
)
from supervised.train import load_artifacts
from supervised.predict import classify_features


logger = logging.getLogger("sentinelflow.classifier")

ARTIFACTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "artifacts",
)


class ThreatClassifier:
    """
    Runtime threat classification engine.
    Wraps preprocessor and model artifacts with lazy loading and error boundaries.
    """

    def __init__(
        self,
        artifacts_dir: Optional[str] = None,
        version: str = "latest",
        threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ):
        self.artifacts_dir = artifacts_dir or ARTIFACTS_DIR
        self.version = version
        self.threshold = threshold

        self._artifacts: Optional[Dict] = None
        self._load_attempted: bool = False
        self._is_available: bool = False
        self._load_error: Optional[str] = None

    def _ensure_loaded(self):
        """Lazy load artifacts once on first inference call."""
        if self._load_attempted:
            return

        self._load_attempted = True
        try:
            self._artifacts = load_artifacts(self.artifacts_dir, version=self.version)
            self._is_available = True
            logger.info(
                f"[ThreatClassifier] Successfully loaded version {self._artifacts['version']} "
                f"with {len(self._artifacts['feature_names'])} features."
            )
        except Exception as exc:
            self._is_available = False
            self._load_error = str(exc)
            logger.warning(
                f"[ThreatClassifier] Could not load model artifacts ({exc}). "
                "Alerts will be raised without supervised threat classification."
            )

    @property
    def is_available(self) -> bool:
        """Returns True if the model and preprocessor are loaded and ready."""
        self._ensure_loaded()
        return self._is_available

    def classify_vector(
        self,
        vector: np.ndarray,
        threshold: Optional[float] = None,
    ) -> Dict:
        """
        Classify a single 77-feature vector.
        """
        self._ensure_loaded()

        if not self._is_available:
            return {
                "predicted_threat": None,
                "confidence": 0.0,
                "alternative_predictions": [],
                "classification_status": "MODEL_UNAVAILABLE",
                "model_version": None,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "supporting_features": None,
                "error": self._load_error,
            }

        cutoff = threshold if threshold is not None else self.threshold

        try:
            results = classify_features(
                model=self._artifacts["model"],
                preprocessor=self._artifacts["preprocessor"],
                label_encoder=self._artifacts["label_encoder"],
                X=vector,
                threshold=cutoff,
                top_k=3,
            )
            res = results[0]

            return {
                "predicted_threat": res["predicted_threat"],
                "confidence": res["confidence"],
                "alternative_predictions": res["alternative_predictions"],
                "classification_status": res["classification_status"].upper(),
                "model_version": self._artifacts["version"],
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "supporting_features": None,
            }

        except Exception as exc:
            logger.error(f"[ThreatClassifier] Inference error: {exc}", exc_info=True)
            return {
                "predicted_threat": None,
                "confidence": 0.0,
                "alternative_predictions": [],
                "classification_status": "ERROR",
                "model_version": self._artifacts.get("version") if self._artifacts else None,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "supporting_features": None,
                "error": str(exc),
            }

    def classify_flow(
        self,
        flow: FlowFeatureAccumulator,
        threshold: Optional[float] = None,
    ) -> Dict:
        """
        Extract features from a flow accumulator and classify it.
        """
        vector = flow.to_vector(
            feature_names=self._artifacts.get("feature_names") if self._is_available else None
        )
        res = self.classify_vector(vector, threshold=threshold)

        # Attach top supporting flow features for operator explainability
        if res.get("classification_status") == "CLASSIFIED":
            raw_feats = flow.extract_features()
            # Select key distinguishing flow metrics
            res["supporting_features"] = {
                "Destination Port": int(raw_feats.get("Destination Port", 0)),
                "Flow Duration (us)": round(raw_feats.get("Flow Duration", 0.0), 2),
                "Total Fwd Packets": int(raw_feats.get("Total Fwd Packets", 0)),
                "Total Bwd Packets": int(raw_feats.get("Total Backward Packets", 0)),
                "Total Length of Fwd Packets": int(raw_feats.get("Total Length of Fwd Packets", 0)),
                "Flow Bytes/s": round(raw_feats.get("Flow Bytes/s", 0.0), 2),
                "SYN Flag Count": int(raw_feats.get("SYN Flag Count", 0)),
                "ACK Flag Count": int(raw_feats.get("ACK Flag Count", 0)),
            }

        return res

    def classify_flows(
        self,
        flows: List[FlowFeatureAccumulator],
        threshold: Optional[float] = None,
    ) -> Dict:
        """
        Classifies a list of candidate flows associated with an anomalous source.
        Returns the dominant, highest-confidence threat classification.
        """
        self._ensure_loaded()

        if not flows:
            return {
                "predicted_threat": None,
                "confidence": 0.0,
                "alternative_predictions": [],
                "classification_status": "NO_CANDIDATE_FLOWS",
                "model_version": self._artifacts.get("version") if self._is_available else None,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "supporting_features": None,
            }

        candidates = []
        for flow in flows:
            c = self.classify_flow(flow, threshold=threshold)
            candidates.append(c)

        # Pick candidate with highest threat confidence
        # Prioritize classified attacks over BENIGN or UNCLASSIFIED
        def rank_key(cand):
            pred = cand.get("predicted_threat")
            conf = cand.get("confidence", 0.0)
            status = cand.get("classification_status")
            is_attack = (pred is not None and pred != "BENIGN" and pred != UNKNOWN_CATEGORY)
            return (1 if is_attack else 0, 1 if status == "CLASSIFIED" else 0, conf)

        best = max(candidates, key=rank_key)
        return best


# Singleton instance for system-wide access
_default_classifier: Optional[ThreatClassifier] = None


def get_threat_classifier() -> ThreatClassifier:
    """Return the global ThreatClassifier singleton."""
    global _default_classifier
    if _default_classifier is None:
        _default_classifier = ThreatClassifier()
    return _default_classifier
