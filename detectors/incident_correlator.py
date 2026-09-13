from typing import Dict, List

from detectors.detection_result import DetectionResult


class IncidentCorrelator:
    """
    Correlates detector signals into operator-facing incidents.

    Detection and correlation are intentionally separate:

        Detector -> detects abnormal behavior
        Correlator -> determines how detected behaviors relate

    The correlator does NOT:
        - change detector thresholds
        - reduce ML sensitivity
        - modify detector scores
        - perform network response
    """

    KNOWN_ATTACK_TYPES = {
        "SYN_FLOOD",
        "PORT_SCAN",
        "C2_BEACONING",
        "DGA_DNS_TUNNELLING",
        "TLS_METADATA_ANOMALY",
        "DATA_EXFILTRATION",
    }

    ML_ATTACK_TYPE = "ML_ANOMALY"

    @staticmethod
    def _copy_detection(
        detection: DetectionResult,
        extra_reasons: List[str],
    ) -> DetectionResult:
        """Copy a detection while preserving its original score/confidence."""

        reasons = list(detection.reasons)

        for reason in extra_reasons:
            if reason not in reasons:
                reasons.append(reason)

        return DetectionResult(
            detected=detection.detected,
            attack_type=detection.attack_type,
            severity=detection.severity,
            score=detection.score,
            confidence=detection.confidence,
            reasons=reasons,
        )

    @staticmethod
    def _relationship(
        source_ip: str,
        communication_context: Dict[str, Dict],
    ) -> Dict:
        return communication_context.get(
            source_ip,
            {},
        )

    def correlate(
        self,
        detections: Dict[str, List[DetectionResult]],
        communication_context: Dict[str, Dict],
        source_features: Dict[str, Dict] = None,
    ) -> Dict[str, List[DetectionResult]]:
        """
        Correlate source-level detections.

        Rules:

        1. Known threat + ML anomaly on the same source:
           known threat remains primary; ML becomes corroboration.

        2. ML anomaly without a known threat:
           ML remains an independent detection.

        3. ML anomaly on a responder is handled by
           correlate_victim_impact().
        """

        correlated = {}

        for source_ip, results in detections.items():

            if source_ip == "__NETWORK__":
                correlated[source_ip] = list(results)
                continue

            known_results = [
                result
                for result in results
                if (
                    result.detected
                    and result.attack_type
                    in self.KNOWN_ATTACK_TYPES
                )
            ]

            ml_results = [
                result
                for result in results
                if (
                    result.detected
                    and result.attack_type
                    == self.ML_ATTACK_TYPE
                )
            ]

            non_ml_results = [
                result
                for result in results
                if (
                    result.detected
                    and result.attack_type
                    != self.ML_ATTACK_TYPE
                )
            ]

            output = list(non_ml_results)

            # ---------------------------------------------------------
            # Overlapping scan + SYN activity
            #
            # Keep both detectors fully sensitive. When a source has
            # an extremely strong multi-port reconnaissance pattern,
            # fold the SYN_FLOOD signal into the PORT_SCAN incident
            # as supporting evidence instead of presenting two
            # independent operator-facing incidents.
            #
            # Detector thresholds and raw results are unchanged.
            # ---------------------------------------------------------

            source = (source_features or {}).get(
                source_ip,
                {},
            )

            unique_ports = source.get(
                "unique_destination_ports",
                0,
            )

            ports_per_destination = source.get(
                "ports_per_destination",
                0.0,
            )

            unique_destinations = source.get(
                "unique_destinations",
                0,
            )

            scan_results = [
                result
                for result in known_results
                if result.attack_type == "PORT_SCAN"
            ]

            syn_results = [
                result
                for result in known_results
                if result.attack_type == "SYN_FLOOD"
            ]

            # Strong multi-port reconnaissance context.
            # This is intentionally contextual rather than a detector
            # threshold: the SYN detector itself remains unchanged.
            strong_scan_context = (
                bool(scan_results)
                and bool(syn_results)
                and unique_ports >= 10
                and ports_per_destination >= 5.0
                and unique_destinations >= 1
            )

            if strong_scan_context:

                supporting_reasons = [
                    "SYN activity correlated with "
                    "multi-port reconnaissance",
                    f"SYN flood detector signal observed across "
                    f"{unique_ports} destination ports",
                ]

                output = [
                    self._copy_detection(
                        result,
                        supporting_reasons,
                    )
                    if result.attack_type == "PORT_SCAN"
                    else result
                    for result in output
                    if result.attack_type != "SYN_FLOOD"
                ]

            # Same-source ML corroboration.
            if known_results and ml_results:

                supporting_reasons = []

                for ml in ml_results:

                    supporting_reasons.append(
                        "ML corroboration: "
                        f"{ml.confidence:.0%} anomaly confidence"
                    )

                    for reason in ml.reasons:
                        supporting_reasons.append(
                            f"ML evidence: {reason}"
                        )

                output = [
                    self._copy_detection(
                        known,
                        supporting_reasons,
                    )
                    for known in output
                ]

            # No known threat on this source.
            elif ml_results:

                output.extend(ml_results)

            correlated[source_ip] = output

        return self.correlate_victim_impact(
            correlated,
            communication_context,
        )

    def correlate_victim_impact(
        self,
        detections: Dict[str, List[DetectionResult]],
        communication_context: Dict[str, Dict],
    ) -> Dict[str, List[DetectionResult]]:
        """
        Correlate responder-side ML anomalies with a known
        initiator-side attack.

        Example:

            10.10.10.10 -> initiator
            10.10.10.20 -> responder

            SYN_FLOOD(10.10.10.10)
            ML_ANOMALY(10.10.10.20)

        becomes:

            SYN_FLOOD(10.10.10.10)

        with the victim ML signal recorded as impact evidence.

        The victim ML detection is removed from the operator-facing
        source list only because it has been incorporated into the
        primary incident. Its original confidence and reasons are
        preserved inside the evidence text.
        """

        # ---------------------------------------------------------
        # Find known attacks and their responders.
        # ---------------------------------------------------------

        attack_relationships = []

        for source_ip, results in detections.items():

            if source_ip == "__NETWORK__":
                continue

            relationship = self._relationship(
                source_ip,
                communication_context,
            )

            initiator_ip = relationship.get(
                "initiator_ip"
            )

            responders = relationship.get(
                "responder_ips",
                [],
            )

            known_results = [
                result
                for result in results
                if (
                    result.detected
                    and result.attack_type
                    in self.KNOWN_ATTACK_TYPES
                )
            ]

            # A known attack is considered attacker-side only
            # when communication context confirms that this source
            # was the initiator.
            if (
                known_results
                and initiator_ip == source_ip
                and responders
            ):
                attack_relationships.append(
                    {
                        "source_ip": source_ip,
                        "responders": responders,
                        "results": known_results,
                    }
                )

        # ---------------------------------------------------------
        # Attach responder-side ML anomalies to the attack.
        # ---------------------------------------------------------

        for attack in attack_relationships:

            attacker = attack["source_ip"]
            responders = set(
                attack["responders"]
            )

            for victim in responders:

                victim_results = detections.get(
                    victim,
                    [],
                )

                victim_ml = [
                    result
                    for result in victim_results
                    if (
                        result.detected
                        and result.attack_type
                        == self.ML_ATTACK_TYPE
                    )
                ]

                if not victim_ml:
                    continue

                impact_reasons = []

                for ml in victim_ml:

                    impact_reasons.append(
                        "Victim-side ML impact anomaly: "
                        f"{ml.confidence:.0%} confidence"
                    )

                    for reason in ml.reasons:
                        impact_reasons.append(
                            f"Victim ML evidence: {reason}"
                        )

                # Add victim evidence to every known attack
                # associated with this attacker.
                attacker_results = detections.get(
                    attacker,
                    [],
                )

                updated_results = []

                for result in attacker_results:

                    if (
                        result.detected
                        and result.attack_type
                        in self.KNOWN_ATTACK_TYPES
                    ):
                        result = self._copy_detection(
                            result,
                            impact_reasons,
                        )

                    updated_results.append(result)

                detections[attacker] = updated_results

                # Remove the responder ML alert from the
                # operator-facing list. The signal is now
                # represented as impact evidence.
                detections[victim] = [
                    result
                    for result in victim_results
                    if not (
                        result.detected
                        and result.attack_type
                        == self.ML_ATTACK_TYPE
                    )
                ]

        return detections
