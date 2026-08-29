from dataclasses import dataclass, field
from typing import Dict


@dataclass
class FeatureContext:
    """
    Central feature context for one detection cycle.

    network:
        Basic network-wide features from the
        fixed observation window.

    security:
        Derived network-wide security features.

    sources:
        Per-source features from the current
        observation window.

    behavior:
        Per-source features from the rolling
        behavioral window.

    beacon:
        STAGE 2 ADDITION.
        Per-source connection-timing features
        (used for C2 beaconing detection).

    dns:
        STAGE 3 ADDITION.
        Per-source DNS query features
        (used for DGA / DNS tunnelling detection).

    tls:
        STAGE 4 ADDITION.
        Per-source TLS ClientHello metadata features
        (used for encrypted-session anomaly detection).
    """

    network: Dict
    security: Dict = field(default_factory=dict)
    sources: Dict[str, Dict] = field(default_factory=dict)
    behavior: Dict[str, Dict] = field(default_factory=dict)
    beacon: Dict[str, Dict] = field(default_factory=dict)
    dns: Dict[str, Dict] = field(default_factory=dict)
    tls: Dict[str, Dict] = field(default_factory=dict)

    def get_source_features(
        self,
        source_ip: str
    ) -> Dict:

        return self.sources.get(
            source_ip,
            {}
        )

    def get_behavior_features(
        self,
        source_ip: str
    ) -> Dict:

        return self.behavior.get(
            source_ip,
            {}
        )

    def get_combined_source_features(
        self,
        source_ip: str
    ) -> Dict:
        """
        Combine current source behavior with rolling
        behavioral, beacon, DNS, and TLS features.

        Network-wide security features are kept separate
        and are not blindly attached to every source.
        """

        current = self.get_source_features(
            source_ip
        )

        combined = dict(current)

        for extra in (
            self.behavior.get(source_ip, {}),
            self.beacon.get(source_ip, {}),
            self.dns.get(source_ip, {}),
            self.tls.get(source_ip, {}),
        ):

            for key, value in extra.items():
                combined[key] = value

        return combined

    def source_ips(self):

        return (
            set(self.sources.keys())
            | set(self.behavior.keys())
            | set(self.beacon.keys())
            | set(self.dns.keys())
            | set(self.tls.keys())
        )
