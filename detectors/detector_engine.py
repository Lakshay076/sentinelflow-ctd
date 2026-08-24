"""
CTD — Detector Engine

Coordinates security detectors.

Detector scopes:

SOURCE
    Uses current per-source features and
    rolling behavioral features.

NETWORK
    Uses network-wide features and
    derived security features.

The engine keeps these scopes separate so that
network-wide behavior is not incorrectly attributed
to an individual source.
"""

from typing import Dict, List

from detectors.detection_result import DetectionResult

from detectors.scan_detector import detect_port_scan
from detectors.syn_flood_detector import detect_syn_flood

from features.feature_context import FeatureContext


class DetectorEngine:

    def __init__(self):

        # ---------------------------------------------
        # Source-level detectors
        # ---------------------------------------------

        self.source_detectors = [
            detect_port_scan,
            detect_syn_flood,
        ]

        # ---------------------------------------------
        # Network-level detectors
        #
        # Currently empty.
        #
        # We will add network-wide detectors here later.
        # ---------------------------------------------

        self.network_detectors = []

    # =================================================
    # SOURCE DETECTION
    # =================================================

    def analyze(
        self,
        features: Dict
    ) -> List[DetectionResult]:
        """
        Run all source-level detectors against
        one combined source feature vector.
        """

        results = []

        for detector in self.source_detectors:

            result = detector(features)

            if result.detected:

                results.append(result)

        return results

    # =================================================
    # NETWORK DETECTION
    # =================================================

    def analyze_network(
        self,
        context: FeatureContext
    ) -> List[DetectionResult]:
        """
        Run network-level detectors.

        Network detectors receive both:

        - basic network features
        - derived security features
        """

        network_features = dict(
            context.network
        )

        network_features.update(
            context.security
        )

        results = []

        for detector in self.network_detectors:

            result = detector(
                network_features
            )

            if result.detected:

                results.append(result)

        return results

    # =================================================
    # COMPLETE CONTEXT ANALYSIS
    # =================================================

    def analyze_context(
        self,
        context: FeatureContext
    ) -> Dict[str, List[DetectionResult]]:
        """
        Analyze every observed source.

        Each source is evaluated using:

        1. Current 1-second source features
        2. Rolling behavioral features

        Network-level detection is handled separately
        by analyze_network().
        """

        detections = {}

        # ---------------------------------------------
        # Source-level detection
        # ---------------------------------------------

        for source_ip in context.source_ips():

            combined_features = (
                context.get_combined_source_features(
                    source_ip
                )
            )

            results = self.analyze(
                combined_features
            )

            detections[source_ip] = results

        # ---------------------------------------------
        # Network-level detection
        # ---------------------------------------------

        network_results = (
            self.analyze_network(context)
        )

        if network_results:

            detections["__NETWORK__"] = (
                network_results
            )

        return detections
