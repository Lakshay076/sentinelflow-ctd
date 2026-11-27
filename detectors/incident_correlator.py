from typing import Dict, List, Optional, Set, Tuple

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
        "UDP_FLOOD",
        "DISTRIBUTED_UDP_FLOOD",
        "PORT_SCAN",
        "C2_BEACONING",
        "DGA_DNS_TUNNELLING",
        "TLS_METADATA_ANOMALY",
        "DATA_EXFILTRATION",
    }

    ML_ATTACK_TYPE = "ML_ANOMALY"

    def __init__(self, correlation_window: float = 15.0):
        self.correlation_window = float(correlation_window)
        self._episodes: Dict[Tuple[str, str], Dict] = {}
        self._step_counter = 0

    def reset(self) -> None:
        """Clear tracked attack episode correlation state."""
        self._episodes.clear()
        self._step_counter = 0

    def _resolve_event_time(self, timestamp: Optional[float]) -> float:
        if timestamp is not None:
            return float(timestamp)
        self._step_counter += 1
        return float(self._step_counter)

    def _prune_expired_episodes(self, event_time: float) -> None:
        expired = [
            key
            for key, ep in self._episodes.items()
            if event_time < ep["last_seen"]
            or (event_time - ep["last_seen"]) > self.correlation_window
        ]
        for key in expired:
            del self._episodes[key]

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

    @staticmethod
    def _ml_reasons_with_prefix(
        ml_results: List[DetectionResult],
        summary_prefix: str,
        evidence_prefix: str,
    ) -> List[str]:
        """Format ML detections as supporting evidence preserving confidence and reasons."""
        reasons = []
        for ml in ml_results:
            summary = f"{summary_prefix}: {ml.confidence:.0%} anomaly confidence"
            if summary not in reasons:
                reasons.append(summary)
            for reason in ml.reasons:
                entry = (
                    reason
                    if reason.startswith(f"{evidence_prefix}:")
                    else f"{evidence_prefix}: {reason}"
                )
                if entry not in reasons:
                    reasons.append(entry)
        return reasons

    def _record_episodes(
        self,
        detections: Dict[str, List[DetectionResult]],
        communication_context: Dict[str, Dict],
        event_time: float,
    ) -> None:
        """Record confirmed known-attack episodes from the current window."""
        for source_ip, results in detections.items():
            if source_ip == "__NETWORK__":
                continue

            relationship = self._relationship(source_ip, communication_context)
            initiator_ip = relationship.get("initiator_ip")
            responders = (
                set(relationship.get("responder_ips", []))
                if initiator_ip == source_ip
                else set()
            )

            for result in results:
                if not result.detected or result.attack_type not in self.KNOWN_ATTACK_TYPES:
                    continue
                key = (source_ip, result.attack_type)
                existing = self._episodes.get(key)
                if existing is not None:
                    existing["last_seen"] = event_time
                    existing["responders"].update(responders)
                    existing["result"] = self._copy_detection(result, [])
                else:
                    self._episodes[key] = {
                        "attacker_ip": source_ip,
                        "attack_type": result.attack_type,
                        "last_seen": event_time,
                        "responders": set(responders),
                        "result": result,
                    }

    def _find_attacker_episode(
        self,
        source_ip: str,
        communication_context: Dict[str, Dict],
        event_time: float,
    ) -> Optional[Dict]:
        """Return most recent non-expired known-attack episode matching source_ip."""
        candidates = [
            ep
            for ep in self._episodes.values()
            if ep["attacker_ip"] == source_ip
            and 0.0 <= (event_time - ep["last_seen"]) <= self.correlation_window
        ]
        if not candidates:
            return None

        candidates.sort(key=lambda ep: ep["last_seen"], reverse=True)
        relationship = self._relationship(source_ip, communication_context)
        current_peers = set(
            relationship.get("responder_ips")
            or relationship.get("observed_peers")
            or []
        )

        for ep in candidates:
            ep_responders = ep["responders"]
            # If both the stored attack episode and the current ML window identify
            # peers, require peer overlap so unrelated later traffic is not merged.
            if ep_responders and current_peers and not (ep_responders & current_peers):
                continue
            return ep

        return None

    @staticmethod
    def _is_confirmed_victim_relationship(
        victim: str,
        attacker: str,
        victim_rel: Dict,
        allow_empty_victim_rel: bool = False,
    ) -> bool:
        """Verify communication context establishes victim as responder to attacker."""
        if not victim_rel:
            return allow_empty_victim_rel

        related_flows = victim_rel.get("related_flows", [])
        if any(
            flow.get("initiator_ip") == attacker
            and flow.get("responder_ip") == victim
            for flow in related_flows
        ):
            return True

        unrelated_initiators = [
            flow.get("initiator_ip")
            for flow in related_flows
            if flow.get("initiator_ip") not in (None, attacker)
        ]
        if unrelated_initiators:
            return False

        return (
            victim_rel.get("initiator_ip") is None
            and attacker in victim_rel.get("observed_peers", [])
        )

    def correlate(
        self,
        detections: Dict[str, List[DetectionResult]],
        communication_context: Dict[str, Dict],
        source_features: Dict[str, Dict] = None,
        timestamp: Optional[float] = None,
    ) -> Dict[str, List[DetectionResult]]:
        """
        Correlate source-level detections across same and consecutive windows.

        Rules:

        1. Known threat + ML anomaly on the same source (same window or within
           the bounded episode correlation_window): known threat remains
           primary; ML becomes corroboration.

        2. ML anomaly without a matching active attack episode:
           ML remains an independent detection.

        3. ML anomaly on a confirmed responder is handled by
           correlate_victim_impact().
        """

        event_time = self._resolve_event_time(timestamp)
        self._prune_expired_episodes(event_time)

        correlated = {}
        current_window_known = {}

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

            # Same-window same-source ML corroboration.
            if known_results and ml_results:
                supporting_reasons = self._ml_reasons_with_prefix(
                    ml_results,
                    summary_prefix="ML corroboration",
                    evidence_prefix="ML evidence",
                )
                output = [
                    self._copy_detection(
                        known,
                        supporting_reasons,
                    )
                    for known in output
                ]

            # Cross-window attacker-side ML corroboration or independent ML.
            elif ml_results:
                episode = self._find_attacker_episode(
                    source_ip=source_ip,
                    communication_context=communication_context,
                    event_time=event_time,
                )
                if episode is not None:
                    supporting_reasons = self._ml_reasons_with_prefix(
                        ml_results,
                        summary_prefix="ML corroboration",
                        evidence_prefix="ML evidence",
                    )
                    output.append(
                        self._copy_detection(
                            episode["result"],
                            supporting_reasons,
                        )
                    )
                else:
                    output.extend(ml_results)

            correlated[source_ip] = output
            if known_results:
                current_window_known[source_ip] = [
                    r for r in output if r.attack_type in self.KNOWN_ATTACK_TYPES
                ]

        # Record only genuine current-window rule detections so ML-only windows
        # cannot artificially extend the episode expiration window.
        self._record_episodes(current_window_known, communication_context, event_time)

        return self.correlate_victim_impact(
            correlated,
            communication_context,
            event_time=event_time,
        )

    def correlate_victim_impact(
        self,
        detections: Dict[str, List[DetectionResult]],
        communication_context: Dict[str, Dict],
        event_time: Optional[float] = None,
    ) -> Dict[str, List[DetectionResult]]:
        """
        Correlate responder-side ML anomalies with a known
        initiator-side attack (same-window or active recent episode).

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
        seen_attackers = set()

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
                seen_attackers.add(source_ip)
                attack_relationships.append(
                    {
                        "source_ip": source_ip,
                        "responders": responders,
                        "results": known_results,
                        "cross_window": False,
                    }
                )

        # Also check recent active episodes for cross-window victim ML anomalies.
        if event_time is not None:
            for ep in sorted(
                self._episodes.values(),
                key=lambda item: item["last_seen"],
                reverse=True,
            ):
                attacker = ep["attacker_ip"]
                if (
                    attacker in seen_attackers
                    or not ep["responders"]
                    or not (0.0 <= (event_time - ep["last_seen"]) <= self.correlation_window)
                ):
                    continue
                seen_attackers.add(attacker)
                attack_relationships.append(
                    {
                        "source_ip": attacker,
                        "responders": sorted(ep["responders"]),
                        "results": [ep["result"]],
                        "cross_window": True,
                    }
                )

        # ---------------------------------------------------------
        # Attach responder-side ML anomalies to the attack.
        # ---------------------------------------------------------

        for attack in attack_relationships:

            attacker = attack["source_ip"]
            responders = set(attack["responders"])
            is_cross_window = attack["cross_window"]

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

                victim_rel = self._relationship(victim, communication_context)
                if not self._is_confirmed_victim_relationship(
                    victim=victim,
                    attacker=attacker,
                    victim_rel=victim_rel,
                    allow_empty_victim_rel=(not is_cross_window),
                ):
                    continue

                impact_reasons = self._ml_reasons_with_prefix(
                    victim_ml,
                    summary_prefix="Victim-side ML impact anomaly",
                    evidence_prefix="Victim ML evidence",
                )

                # Add victim evidence to every known attack
                # associated with this attacker (creating or enriching
                # the attacker's entry when attached cross-window).
                attacker_results = list(detections.get(attacker, []))
                has_known = any(
                    r.detected and r.attack_type in self.KNOWN_ATTACK_TYPES
                    for r in attacker_results
                )
                if not has_known and is_cross_window:
                    attacker_results.extend(attack["results"])

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
