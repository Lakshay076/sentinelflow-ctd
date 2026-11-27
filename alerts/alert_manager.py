from typing import Dict, List, Optional

from alerts.alert_record import AlertRecord
from alerts.alert_store import AlertStore
from detectors.detection_result import DetectionResult
from detectors.incident_correlator import IncidentCorrelator


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

    SEVERITY_RANK = {
        "NONE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    KNOWN_ATTACK_TYPES = IncidentCorrelator.KNOWN_ATTACK_TYPES

    def __init__(
        self,
        resolve_after: float = 300.0,
        store: Optional[AlertStore] = None,
        db_path: Optional[str] = None,
        correlation_window: float = 15.0,
    ):

        if resolve_after <= 0:
            raise ValueError(
                "resolve_after must be greater than 0"
            )

        self.resolve_after = resolve_after
        self.correlation_window = float(correlation_window)

        self.store = store if store is not None else AlertStore(db_path=db_path)

    @staticmethod
    def _merge_unique_strings(existing: Optional[List[str]], new: Optional[List[str]]) -> List[str]:
        merged = list(existing or [])
        for item in new or []:
            if item and item not in merged:
                merged.append(item)
        return merged

    @staticmethod
    def _merge_related_flows(existing: Optional[List[dict]], new: Optional[List[dict]]) -> List[dict]:
        merged = []
        seen = set()
        for flow in list(existing or []) + list(new or []):
            key = (
                flow.get("flow_id")
                or (
                    flow.get("src_ip"),
                    flow.get("dst_ip"),
                    flow.get("src_port"),
                    flow.get("dst_port"),
                    flow.get("protocol"),
                )
            )
            if key not in seen:
                seen.add(key)
                merged.append(flow)
        return merged[-50:]

    def _higher_severity(self, left: str, right: str) -> str:
        return left if self.SEVERITY_RANK.get(left, 0) >= self.SEVERITY_RANK.get(right, 0) else right

    @staticmethod
    def _ml_corroboration_reasons(ml_alert: AlertRecord, victim: bool = False) -> List[str]:
        prefix = "Victim-side ML impact anomaly" if victim else "ML corroboration"
        evidence_prefix = "Victim ML evidence" if victim else "ML evidence"
        reasons = [f"{prefix}: {ml_alert.confidence:.0%} anomaly confidence"]
        for reason in ml_alert.reasons:
            if reason.startswith(f"{evidence_prefix}:") or reason.startswith(f"{prefix}:"):
                reasons.append(reason)
            else:
                reasons.append(f"{evidence_prefix}: {reason}")
        return reasons

    def _absorb_precursor_ml_alerts(
        self,
        source_ip: str,
        responder_ips: List[str],
        timestamp: float,
        reasons: List[str],
    ) -> List[str]:
        """Fold recent active precursor ML alerts from the same attack episode."""
        merged_reasons = list(reasons)
        known_responders = set(responder_ips or [])

        for alert in self.store.active():
            if alert.attack_type != "ML_ANOMALY":
                continue
            age = timestamp - alert.last_seen
            if age < 0 or age > self.correlation_window:
                continue

            same_attacker = alert.source_ip == source_ip
            if same_attacker:
                ml_peers = set(alert.responder_ips or [])
                if not ml_peers:
                    for fl in alert.related_flows or []:
                        if fl.get("src_ip") == source_ip and fl.get("dst_ip"):
                            ml_peers.add(fl["dst_ip"])
                        elif fl.get("dst_ip") == source_ip and fl.get("src_ip"):
                            ml_peers.add(fl["src_ip"])
                if known_responders and ml_peers and not (known_responders & ml_peers):
                    continue
                for r in self._ml_corroboration_reasons(alert, victim=False):
                    if r not in merged_reasons:
                        merged_reasons.append(r)
                self.store.resolve(alert_id=alert.alert_id, timestamp=timestamp)
                continue

            if alert.source_ip in known_responders:
                flows = alert.related_flows or []
                is_responder = any(
                    fl.get("initiator_ip") == source_ip and fl.get("responder_ip") == alert.source_ip
                    for fl in flows
                )
                if not is_responder:
                    continue
                for r in self._ml_corroboration_reasons(alert, victim=True):
                    if r not in merged_reasons:
                        merged_reasons.append(r)
                self.store.resolve(alert_id=alert.alert_id, timestamp=timestamp)

        return merged_reasons

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

            is_known_attack = detection.attack_type in self.KNOWN_ATTACK_TYPES
            reasons = list(detection.reasons)

            if existing is None:
                if is_known_attack:
                    reasons = self._absorb_precursor_ml_alerts(
                        source_ip=source_ip,
                        responder_ips=responder_ips,
                        timestamp=timestamp,
                        reasons=reasons,
                    )

                alert = self.store.create(
                    source_ip=source_ip,
                    attack_type=detection.attack_type,
                    severity=detection.severity,
                    confidence=detection.confidence,
                    timestamp=timestamp,
                    reasons=reasons,
                    initiator_ip=initiator_ip,
                    responder_ips=responder_ips,
                    related_flows=related_flows,
                )

            else:
                merged_responders = self._merge_unique_strings(
                    existing.responder_ips,
                    responder_ips,
                )
                merged_initiator = (
                    initiator_ip
                    if initiator_ip is not None
                    else existing.initiator_ip
                )
                merged_flows = self._merge_related_flows(
                    existing.related_flows,
                    related_flows,
                )
                merged_reasons = self._merge_unique_strings(
                    existing.reasons,
                    reasons,
                )
                if is_known_attack:
                    merged_reasons = self._absorb_precursor_ml_alerts(
                        source_ip=source_ip,
                        responder_ips=merged_responders,
                        timestamp=timestamp,
                        reasons=merged_reasons,
                    )

                updated_alert = self.store.update(
                    alert_id=existing.alert_id,
                    timestamp=timestamp,
                    severity=self._higher_severity(existing.severity, detection.severity),
                    confidence=max(existing.confidence, detection.confidence),
                    event_count=existing.event_count + 1,
                    reasons=merged_reasons,
                    initiator_ip=merged_initiator,
                    responder_ips=merged_responders,
                    related_flows=merged_flows,
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
