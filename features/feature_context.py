from dataclasses import dataclass
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
    """

    network: Dict
    security: Dict
    sources: Dict[str, Dict]
    behavior: Dict[str, Dict]

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
        Combine current source behavior with
        rolling behavioral features.

        Network-wide security features are kept
        separate and are not blindly attached to
        every source.
        """

        current = self.get_source_features(
            source_ip
        )

        behavior = self.get_behavior_features(
            source_ip
        )

        combined = dict(current)

        for key, value in behavior.items():

            combined[key] = value

        return combined

    def source_ips(self):

        return (
            set(self.sources.keys())
            |
            set(self.behavior.keys())
        )
