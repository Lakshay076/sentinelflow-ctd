"""
CTD — Detector Engine

Coordinates security detectors.

Detector scopes:

SOURCE
    Uses current per-source features, rolling behavioral
    features, beacon timing features, DNS features, and
    TLS metadata features.

NETWORK
    Uses network-wide features and derived security
    features.

The engine keeps these scopes separate so that
network-wide behavior is not incorrectly attributed
to an individual source.
"""

from typing import Dict, List

from detectors.detection_result import DetectionResult

from detectors.scan_detector import detect_port_scan
from detectors.syn_flood_detector import detect_syn_flood
from detectors.exfiltration_detector import detect_exfiltration
from detectors.beacon_detector import detect_c2_beaconing
from detectors.dga_detector import detect_dga_dns
from detectors.tls_detector import detect_tls_anomaly

from features.feature_context import FeatureContext


class DetectorEngine:

    def __init__(self, use_ml: bool = True):

        # ---------------------------------------------
        # Source-level detectors.
        #
        # 5 rule-based detectors covering all 6 required
        # threat types from the problem statement:
        #
        #   detect_port_scan        -> reconnaissance
        #   detect_syn_flood        -> volumetric DDoS
        #   detect_exfiltration     -> data exfiltration
        #   detect_c2_beaconing     -> botnet C2 beaconing
        #   detect_dga_dns          -> DGA / DNS tunnelling
        #   detect_tls_anomaly      -> encrypted malware
        # ---------------------------------------------

        self.source_detectors = [
            detect_port_scan,
            detect_syn_flood,
            detect_exfiltration,
            detect_c2_beaconing,
            detect_dga_dns,
            detect_tls_anomaly,
        ]

        # ---------------------------------------------
        # STAGE 5 ADDITION: the ML anomaly detector.
        #
        # This is added separately (not just appended to
        # source_detectors above) because it needs a
        # trained model file to exist on disk. If the
        # model hasn't been trained yet, it safely does
        # nothing instead of crashing -- see
        # inference/ml_detector.py for details.
        #
        # Set use_ml=False to run in rule-based-only mode.
        # ---------------------------------------------

        if use_ml:

            from inference.ml_detector import detect_ml_anomaly

            self.source_detectors.append(
                detect_ml_anomaly
            )

        # ---------------------------------------------
        # Network-level detectors.
        #
        # Currently empty -- reserved for future
        # network-wide detection logic.
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
    # COMMUNICATION CONTEXT
    # =================================================

    def get_communication_context(
        self,
        context: FeatureContext,
    ) -> Dict[str, Dict]:
        """Return observed communication relationships by source.

        This is enrichment only. It does not affect detector
        thresholds, scores, confidence, or ML sensitivity.
        """

        from detectors.correlation import (
            get_source_relationships,
        )

        communications = context.get_communications()

        # Start with the same source population used by
        # the detector pipeline. Communication context is
        # enrichment only and must not create new ML sources.
        source_ips = set(context.source_ips())

        # Communication records may contain useful relationship
        # information for an already-observed source. Add only
        # endpoints that are already represented in the context's
        # source-level feature population.
        result = {}

        for source_ip in source_ips:

            result[source_ip] = get_source_relationships(
                source_ip,
                communications,
            )

        return result

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
        3. Beacon timing features
        4. DNS features
        5. TLS metadata features

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
