from typing import Any, Dict, List, Optional

from alerts.alert_record import AlertRecord
from alerts.alert_store import AlertStore
from detectors.detection_result import DetectionResult


class AlertManager:
    """
    Converts detector results into security incidents.

    Responsibilities:

    1. Create new incidents.
    2. Update existing incidents.
    3. Resolve inactive incidents.
    4. Preserve incident history.
    5. Enrich incidents with observed communication relationships.
    6. Perform supervised ML threat classification on eligible anomalies.

    This component is detection-only.

    It NEVER:
        - blocks an IP
        - changes firewall rules
        - kills connections
        - modifies packets
    """

    def __init__(
        self,
        resolve_after: float = 300.0,
        classifier: Optional[Any] = None,
    ):

        if resolve_after <= 0:
            raise ValueError(
                "resolve_after must be greater than 0"
            )

        self.resolve_after = resolve_after

        self.store = AlertStore()

        if classifier is not None:
            self.classifier = classifier
        else:
            try:
                from supervised.classifier import get_threat_classifier
                self.classifier = get_threat_classifier()
            except Exception:
                self.classifier = None

    @staticmethod
    def _relationship_fields(
        communication_context: Optional[Dict],
    ):
        """
        Extract communication-role information for an alert.

        The detector source remains authoritative. Communication context
        only enriches the incident with observed initiator/responder roles
        and related flows.
        """

        if not communication_context:
            return None, [], []

        initiator_ip = communication_context.get(
            "initiator_ip"
        )

        responder_ips = communication_context.get(
            "responder_ips",
            []
        )

        related_flows = communication_context.get(
            "related_flows",
            []
        )

        return (
            initiator_ip,
            responder_ips,
            related_flows,
        )

    def process(
        self,
        source_ip: str,
        detections: List[DetectionResult],
        timestamp: float,
        communication_context: Optional[Dict] = None,
        candidate_flows: Optional[List[Any]] = None,
    ) -> List[AlertRecord]:
        """
        Process detector results for one source.

        communication_context contains the observed relationship for this
        source in the current observation window.

        candidate_flows contains FlowFeatureAccumulators for this source,
        used by the supervised classifier to categorize anomalies.

        Returns the alerts that were created or updated.
        """

        active_alerts = []

        (
            initiator_ip,
            responder_ips,
            related_flows,
        ) = self._relationship_fields(
            communication_context
        )

        for detection in detections:

            if not detection.detected:
                continue

            # -------------------------------------------------------------
            # PHASE 3: Supervised threat classification on eligible anomalies
            # -------------------------------------------------------------
            # Eligible anomalies: ML_ANOMALY detections from Stage 1 Isolation Forest.
            if detection.attack_type == "ML_ANOMALY":
                if not self.classifier or not getattr(self.classifier, "is_available", False):
                    detection.classification_status = "MODEL_UNAVAILABLE"
                elif not candidate_flows:
                    detection.classification_status = "NO_CANDIDATE_FLOWS"
                else:
                    try:
                        clf_result = self.classifier.classify_flows(candidate_flows)
                        if clf_result:
                            detection.predicted_threat = clf_result.get("predicted_threat")
                            detection.threat_confidence = clf_result.get("confidence")
                            detection.alternative_predictions = clf_result.get("alternative_predictions", [])
                            detection.classification_status = clf_result.get("classification_status")
                            detection.model_version = clf_result.get("model_version")
                            detection.feature_schema_version = clf_result.get("feature_schema_version")
                            detection.supporting_features = clf_result.get("supporting_features")

                            pred = detection.predicted_threat
                            conf = detection.threat_confidence
                            status = detection.classification_status
                            if status == "CLASSIFIED" and pred:
                                expl = f"Supervised ML classification: {pred} (confidence: {conf:.0%})"
                                if expl not in detection.reasons:
                                    detection.reasons.append(expl)
                            elif status == "LOW_CONFIDENCE" or pred == "UNCLASSIFIED":
                                expl = f"Supervised ML classification: UNCLASSIFIED (low confidence: {conf:.0%})"
                                if expl not in detection.reasons:
                                    detection.reasons.append(expl)
                    except Exception:
                        # The classifier must never suppress an existing alert if inference fails
                        detection.classification_status = "ERROR"

            existing = self.store.find_active(
                source_ip=source_ip,
                attack_type=detection.attack_type,
            )

            if existing is None:

                alert = self.store.create(
                    source_ip=source_ip,
                    attack_type=detection.attack_type,
                    severity=detection.severity,
                    confidence=detection.confidence,
                    timestamp=timestamp,
                    reasons=detection.reasons,
                    initiator_ip=initiator_ip,
                    responder_ips=responder_ips,
                    related_flows=related_flows,
                    predicted_threat=detection.predicted_threat,
                    threat_confidence=detection.threat_confidence,
                    alternative_predictions=detection.alternative_predictions,
                    classification_status=detection.classification_status,
                    model_version=detection.model_version,
                    feature_schema_version=detection.feature_schema_version,
                    supporting_features=detection.supporting_features,
                )

            else:

                updated_alert = self.store.update(
                    alert_id=existing.alert_id,
                    timestamp=timestamp,
                    severity=detection.severity,
                    confidence=detection.confidence,
                    event_count=existing.event_count + 1,
                    reasons=detection.reasons,
                    initiator_ip=initiator_ip,
                    responder_ips=responder_ips,
                    related_flows=related_flows,
                    predicted_threat=detection.predicted_threat,
                    threat_confidence=detection.threat_confidence,
                    alternative_predictions=detection.alternative_predictions,
                    classification_status=detection.classification_status,
                    model_version=detection.model_version,
                    feature_schema_version=detection.feature_schema_version,
                    supporting_features=detection.supporting_features,
                )

                if updated_alert is None:
                    continue

                alert = updated_alert

            active_alerts.append(alert)

        return active_alerts

    def resolve_stale(
        self,
        timestamp: float,
    ) -> List[AlertRecord]:
        """
        Resolve alerts that have not been observed recently.

        This only changes the alert's state.
        It does NOT perform any defensive network action.
        """

        resolved = []

        for alert in self.store.active():

            inactivity = (
                timestamp - alert.last_seen
            )

            if inactivity >= self.resolve_after:

                resolved_alert = self.store.resolve(
                    alert_id=alert.alert_id,
                    timestamp=timestamp,
                )

                if resolved_alert is not None:
                    resolved.append(resolved_alert)

        return resolved

    def active_alerts(self) -> List[AlertRecord]:
        return self.store.active()

    def history(self) -> List[AlertRecord]:
        return self.store.all()
