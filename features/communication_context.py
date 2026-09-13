from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


@dataclass
class Communication:
    """
    Metadata describing one observed bidirectional flow.

    Roles are inferred from TCP handshake evidence.
    No application payload is stored or inspected here.
    """

    flow_id: str
    protocol: str

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    initiator_ip: Optional[str] = None
    responder_ip: Optional[str] = None


class CommunicationContext:
    """
    Tracks communication relationships observed during the
    current detection window.

    This is deliberately separate from numeric ML features.
    It provides relationship context for alert enrichment
    and cross-detector correlation.
    """

    def __init__(self):
        self._communications: Dict[str, Communication] = {}

    @staticmethod
    def _flow_id(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
    ) -> str:
        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:
            left = endpoint_a
            right = endpoint_b
        else:
            left = endpoint_b
            right = endpoint_a

        return (
            f"{left[0]}:{left[1]}"
            f"<->{right[0]}:{right[1]}"
            f"/{protocol.upper()}"
        )

    def record(self, flow, packet=None) -> None:
        """
        Record the current state of a Flow.

        FlowEngine remains the primary source of truth for
        communication roles.

        Direct TCP handshake evidence is also accepted so that
        SYN-flood connections are attributed correctly even when
        the connection never completes the handshake.
        """

        flow_id = self._flow_id(
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol,
        )

        initiator_ip = flow.initiator_ip
        responder_ip = flow.responder_ip

        # A SYN without ACK is direct evidence that the sender
        # initiated this TCP connection.
        if (
            packet is not None
            and flow.protocol.upper() == "TCP"
            and getattr(packet, "tcp_flags", None)
        ):
            flags = str(packet.tcp_flags)

            if "S" in flags and "A" not in flags:
                initiator_ip = packet.src_ip
                responder_ip = packet.dst_ip

            # SYN+ACK provides reverse-direction confirmation.
            elif "S" in flags and "A" in flags:
                if initiator_ip is None:
                    initiator_ip = packet.dst_ip

                if responder_ip is None:
                    responder_ip = packet.src_ip

        self._communications[flow_id] = Communication(
            flow_id=flow_id,
            protocol=flow.protocol,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            initiator_ip=initiator_ip,
            responder_ip=responder_ip,
        )

    def snapshot(self) -> List[Dict]:
        """
        Return a copy of relationships observed in this window.
        """

        return [
            asdict(communication)
            for communication in self._communications.values()
        ]

    def source_relationships(self) -> Dict[str, List[Dict]]:
        """
        Group communication relationships by source/endpoint.

        This is useful for source-centric detectors while
        preserving the underlying flow relationships.
        """

        result: Dict[str, List[Dict]] = {}

        for communication in self._communications.values():
            data = asdict(communication)

            for ip in {
                communication.src_ip,
                communication.dst_ip,
                communication.initiator_ip,
                communication.responder_ip,
            }:
                if ip is None:
                    continue

                result.setdefault(ip, []).append(data)

        return result

    def reset(self) -> None:
        """
        Start a fresh relationship observation window.
        """

        self._communications.clear()
