from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DetectionResult:
    detected: bool
    attack_type: Optional[str]
    severity: str
    score: int
    confidence: float
    reasons: List[str] = field(default_factory=list)

    # Supervised Threat Classification Fields (Phase 3)
    predicted_threat: Optional[str] = None
    threat_confidence: Optional[float] = None
    alternative_predictions: List[dict] = field(default_factory=list)
    classification_status: Optional[str] = None
    model_version: Optional[str] = None
    feature_schema_version: Optional[str] = None
    supporting_features: Optional[dict] = None

    def to_dict(self):
        return {
            "detected": self.detected,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "predicted_threat": self.predicted_threat,
            "threat_confidence": self.threat_confidence,
            "alternative_predictions": self.alternative_predictions,
            "classification_status": self.classification_status,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version,
            "supporting_features": self.supporting_features,
        }
