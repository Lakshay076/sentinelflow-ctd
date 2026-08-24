from typing import Dict, List, Optional

from alerts.alert_record import AlertRecord


class AlertStore:
    """
    In-memory persistent-for-process alert history.

    Later this class will be replaced or backed by a real
    database such as SQLite/PostgreSQL.

    It does NOT perform any network response.
    """

    def __init__(self):
        self.alerts: Dict[int, AlertRecord] = {}

        self.next_id = 1

    def create(
        self,
        source_ip: str,
        attack_type: str,
        severity: str,
        confidence: float,
        timestamp: float,
        reasons: List[str],
    ) -> AlertRecord:

        alert = AlertRecord(
            alert_id=self.next_id,
            source_ip=source_ip,
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
            first_seen=timestamp,
            last_seen=timestamp,
            reasons=reasons,
        )

        self.alerts[self.next_id] = alert

        self.next_id += 1

        return alert

    def get(self, alert_id: int) -> Optional[AlertRecord]:
        return self.alerts.get(alert_id)

    def all(self) -> List[AlertRecord]:
        return list(self.alerts.values())

    def active(self) -> List[AlertRecord]:
        return [
            alert
            for alert in self.alerts.values()
            if alert.status == "ACTIVE"
        ]

    def resolved(self) -> List[AlertRecord]:
        return [
            alert
            for alert in self.alerts.values()
            if alert.status == "RESOLVED"
        ]

    def find_active(
        self,
        source_ip: str,
        attack_type: str,
    ) -> Optional[AlertRecord]:

        for alert in self.alerts.values():

            if alert.status != "ACTIVE":
                continue

            if alert.source_ip != source_ip:
                continue

            if alert.attack_type != attack_type:
                continue

            return alert

        return None
