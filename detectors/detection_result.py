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

    def to_dict(self):
        return {
            "detected": self.detected,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "reasons": self.reasons,
        }
