"""
CTD — Detection Correlation and Communication Context

Enriches detections with observed communication relationships.

This module does NOT change detector thresholds, scores, or
ML sensitivity. It only explains who communicated with whom
for an already-detected source.

TCP roles come from FlowEngine handshake inference.
For non-TCP traffic, observed src/dst direction is preserved
without inventing initiator/responder roles.
"""

from typing import Dict, List, Optional


def _unique(values: List[Optional[str]]) -> List[str]:
    """Return non-empty unique values while preserving order."""

    result = []

    for value in values:
        if value and value not in result:
            result.append(value)

    return result


def get_source_relationships(
    source_ip: str,
    communications: List[Dict],
) -> Dict:
    """
    Build communication context for one detected source.

    Returns:
        {
            "source_ip": ...,
            "initiator_ip": ...,
            "responder_ips": [...],
            "observed_peers": [...],
            "related_flows": [...]
        }
    """

    related_flows = []

    for communication in communications:

        if (
            communication.get("src_ip") != source_ip
            and communication.get("dst_ip") != source_ip
            and communication.get("initiator_ip") != source_ip
            and communication.get("responder_ip") != source_ip
        ):
            continue

        related_flows.append(communication)

    initiators = []
    responders = []
    peers = []

    for communication in related_flows:

        initiator = communication.get("initiator_ip")
        responder = communication.get("responder_ip")

        if initiator == source_ip:
            initiators.append(source_ip)

            if responder:
                peers.append(responder)

        elif responder == source_ip:
            responders.append(source_ip)

            if initiator:
                peers.append(initiator)

        else:
            # Non-TCP or incomplete-handshake context.
            src_ip = communication.get("src_ip")
            dst_ip = communication.get("dst_ip")

            if src_ip == source_ip:
                peers.append(dst_ip)

            elif dst_ip == source_ip:
                peers.append(src_ip)

    return {
        "source_ip": source_ip,
        "initiator_ip": (
            source_ip
            if source_ip in initiators
            else None
        ),
        "responder_ips": _unique(
            [
                communication.get("responder_ip")
                for communication in related_flows
                if communication.get("initiator_ip") == source_ip
            ]
        ),
        "observed_peers": _unique(peers),
        "related_flows": related_flows,
    }
