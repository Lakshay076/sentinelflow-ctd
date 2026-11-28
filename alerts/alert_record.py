from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AlertRecord:
    """
    Represents one detected security incident.

    CTD is detection-only:
    this record does not perform any response or blocking.
    """

    alert_id: int

    source_ip: str
    attack_type: str

    severity: str
    confidence: float

    first_seen: float
    last_seen: float

    status: str = "ACTIVE"

    event_count: int = 1

    reasons: List[str] = field(default_factory=list)

    # Communication enrichment.
    # These fields describe observed relationships only.
    # They do not imply that CTD performed any network action.
    initiator_ip: Optional[str] = None

    responder_ips: List[str] = field(
        default_factory=list
    )

    related_flows: List[dict] = field(
        default_factory=list
    )

    resolved_at: Optional[float] = None

    # Supervised Threat Classification Fields (Phase 3)
    predicted_threat: Optional[str] = None
    threat_confidence: Optional[float] = None
    alternative_predictions: List[dict] = field(default_factory=list)
    classification_status: Optional[str] = None
    model_version: Optional[str] = None
    feature_schema_version: Optional[str] = None
    supporting_features: Optional[dict] = None

    def duration(self) -> float:
        """
        Return the duration of the incident.
        """

        end_time = self.last_seen

        return max(
            0.0,
            end_time - self.first_seen
        )

    def update(
        self,
        timestamp: float,
        severity: str,
        confidence: float,
        reasons: List[str],
        predicted_threat: Optional[str] = None,
        threat_confidence: Optional[float] = None,
        alternative_predictions: Optional[List[dict]] = None,
        classification_status: Optional[str] = None,
        model_version: Optional[str] = None,
        feature_schema_version: Optional[str] = None,
        supporting_features: Optional[dict] = None,
    ):
        """
        Update an existing active incident.
        """

        self.last_seen = timestamp

        self.severity = severity

        self.confidence = max(
            self.confidence,
            confidence
        )

        self.event_count += 1

        self.reasons = reasons

        if predicted_threat is not None:
            self.predicted_threat = predicted_threat
        if threat_confidence is not None:
            self.threat_confidence = threat_confidence
        if alternative_predictions is not None:
            self.alternative_predictions = alternative_predictions
        if classification_status is not None:
            self.classification_status = classification_status
        if model_version is not None:
            self.model_version = model_version
        if feature_schema_version is not None:
            self.feature_schema_version = feature_schema_version
        if supporting_features is not None:
            self.supporting_features = supporting_features

    def resolve(self, timestamp: float):
        """
        Mark the incident as resolved.

        No network action is performed.
        """

        if self.status == "RESOLVED":
            return

        self.status = "RESOLVED"

        self.resolved_at = timestamp

    def to_dict(self):
        return {
            "alert_id": self.alert_id,
            "source_ip": self.source_ip,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "resolved_at": self.resolved_at,
            "status": self.status,
            "event_count": self.event_count,
            "duration": self.duration(),
            "reasons": self.reasons,
            "initiator_ip": self.initiator_ip,
            "responder_ips": self.responder_ips,
            "related_flows": self.related_flows,
            "predicted_threat": self.predicted_threat,
            "threat_confidence": self.threat_confidence,
            "alternative_predictions": self.alternative_predictions,
            "classification_status": self.classification_status,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version,
            "supporting_features": self.supporting_features,
        }
