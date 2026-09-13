from typing import Dict, List, Optional

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
    ):

        if resolve_after <= 0:
            raise ValueError(
                "resolve_after must be greater than 0"
            )

        self.resolve_after = resolve_after

        self.store = AlertStore()

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
    ) -> List[AlertRecord]:
        """
        Process detector results for one source.

        communication_context contains the observed relationship for this
        source in the current observation window.

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
