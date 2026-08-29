from dataclasses import dataclass
from typing import Dict, Tuple

from collector.packet_record import PacketRecord


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    start_time: float
    last_seen: float

    packets: int = 0
    bytes: int = 0

    forward_packets: int = 0
    backward_packets: int = 0

    forward_bytes: int = 0
    backward_bytes: int = 0

    def duration(self) -> float:
        return self.last_seen - self.start_time


class FlowEngine:

    def __init__(self, timeout=60):
        self.flows: Dict[Tuple, Flow] = {}
        self.timeout = timeout

    def _get_key(
        self,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    ):

        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:
            return (endpoint_a, endpoint_b, protocol)

        return (endpoint_b, endpoint_a, protocol)

    def is_new_flow(
        self,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    ) -> bool:
        """
        STAGE 2 ADDITION.

        Check whether this packet would start a brand-new
        flow, WITHOUT changing any state.

        This is used by the beacon tracker: it only cares
        about the moment a NEW connection begins, not every
        packet inside it.
        """

        key = self._get_key(
            src_ip, dst_ip, src_port, dst_port, protocol
        )

        return key not in self.flows

    def process_packet(self, packet: PacketRecord):

        src_port = packet.src_port or 0
        dst_port = packet.dst_port or 0

        key = self._get_key(
            packet.src_ip,
            packet.dst_ip,
            src_port,
            dst_port,
            packet.protocol
        )

        if key not in self.flows:

            flow = Flow(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                last_seen=packet.timestamp
            )

            self.flows[key] = flow

        else:
            flow = self.flows[key]

        flow.last_seen = packet.timestamp

        flow.packets += 1
        flow.bytes += packet.packet_length

        if (
            packet.src_ip == flow.src_ip
            and packet.dst_ip == flow.dst_ip
            and src_port == flow.src_port
            and dst_port == flow.dst_port
        ):

            flow.forward_packets += 1
            flow.forward_bytes += packet.packet_length

        else:

            flow.backward_packets += 1
            flow.backward_bytes += packet.packet_length

        return flow

    def remove_expired_flows(self):

        current_time = __import__("time").time()

        expired = []

        for key, flow in self.flows.items():

            if current_time - flow.last_seen > self.timeout:
                expired.append(key)

        for key in expired:
            del self.flows[key]

        return len(expired)
