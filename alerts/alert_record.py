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

    resolved_at: Optional[float] = None

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
        }
