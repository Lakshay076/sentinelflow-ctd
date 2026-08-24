from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class ObservationWindow:
    """
    Fixed-duration observation window.

    Only packet metadata is collected.
    Packet payloads are never inspected.
    """

    window_start: float

    packets: int = 0
    bytes: int = 0

    # Directional traffic
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0

    # Packet size
    total_packet_size: int = 0

    # Protocol statistics
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0

    # TCP flags
    tcp_syn: int = 0
    tcp_ack: int = 0
    tcp_rst: int = 0

    # First observed direction
    forward_src_ip: str = ""
    forward_dst_ip: str = ""
    forward_src_port: int = 0
    forward_dst_port: int = 0

    # Diversity
    source_ips: Set[str] = field(default_factory=set)
    destination_ips: Set[str] = field(default_factory=set)
    destination_ports: Set[int] = field(default_factory=set)

    # Bidirectional flows
    flows: Set[str] = field(default_factory=set)

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        packet_bytes: int,
        src_port: int = 0,
        dst_port: int = 0,
        tcp_syn: bool = False,
        tcp_ack: bool = False,
        tcp_rst: bool = False,
    ):
        """
        Add one packet's metadata to the current window.
        """

        # --------------------------------------------------
        # Basic traffic statistics
        # --------------------------------------------------

        self.packets += 1
        self.bytes += packet_bytes
        self.total_packet_size += packet_bytes

        # --------------------------------------------------
        # Source / destination statistics
        # --------------------------------------------------

        self.source_ips.add(src_ip)
        self.destination_ips.add(dst_ip)

        if dst_port:
            self.destination_ports.add(dst_port)

        # --------------------------------------------------
        # Normalize protocol
        # --------------------------------------------------

        protocol = protocol.upper()

        # --------------------------------------------------
        # Protocol statistics
        # --------------------------------------------------

        if protocol == "TCP":

            self.tcp_packets += 1

            if tcp_syn:
                self.tcp_syn += 1

            if tcp_ack:
                self.tcp_ack += 1

            if tcp_rst:
                self.tcp_rst += 1

        elif protocol == "UDP":

            self.udp_packets += 1

        elif protocol == "ICMP":

            self.icmp_packets += 1

        # --------------------------------------------------
        # Determine packet direction
        # --------------------------------------------------

        if self.forward_src_ip == "":

            # First packet establishes forward direction.

            self.forward_src_ip = src_ip
            self.forward_dst_ip = dst_ip
            self.forward_src_port = src_port
            self.forward_dst_port = dst_port

            self.forward_packets += 1
            self.forward_bytes += packet_bytes

        elif (
            src_ip == self.forward_src_ip
            and dst_ip == self.forward_dst_ip
            and src_port == self.forward_src_port
            and dst_port == self.forward_dst_port
        ):

            # Same direction as first packet.

            self.forward_packets += 1
            self.forward_bytes += packet_bytes

        else:

            # Reverse direction.

            self.backward_packets += 1
            self.backward_bytes += packet_bytes

        # --------------------------------------------------
        # Direction-independent flow identifier
        # --------------------------------------------------
        #
        # A -> B
        # B -> A
        #
        # are treated as the same bidirectional flow.
        # --------------------------------------------------

        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:

            flow_id = (
                f"{src_ip}:{src_port}"
                f"<->{dst_ip}:{dst_port}"
                f"/{protocol}"
            )

        else:

            flow_id = (
                f"{dst_ip}:{dst_port}"
                f"<->{src_ip}:{src_port}"
                f"/{protocol}"
            )

        self.flows.add(flow_id)

    def to_features(self, duration: float) -> Dict:
        """
        Convert the completed window into a feature vector.
        """

        duration = max(duration, 0.000001)

        # --------------------------------------------------
        # Derived traffic features
        # --------------------------------------------------

        mean_packet_size = (
            self.bytes / max(self.packets, 1)
        )

        forward_backward_packet_ratio = (
            self.forward_packets
            / max(self.backward_packets, 1)
        )

        forward_backward_byte_ratio = (
            self.forward_bytes
            / max(self.backward_bytes, 1)
        )

        syn_rate = self.tcp_syn / duration
        rst_rate = self.tcp_rst / duration

        # --------------------------------------------------
        # Feature vector
        # --------------------------------------------------

        return {

            # Window
            "window_duration": duration,

            # Traffic volume
            "packets": self.packets,
            "bytes": self.bytes,

            "packets_per_second": (
                self.packets / duration
            ),

            "bytes_per_second": (
                self.bytes / duration
            ),

            "mean_packet_size": mean_packet_size,

            # Direction
            "forward_packets": self.forward_packets,
            "backward_packets": self.backward_packets,

            "forward_bytes": self.forward_bytes,
            "backward_bytes": self.backward_bytes,

            "forward_backward_packet_ratio": (
                forward_backward_packet_ratio
            ),

            "forward_backward_byte_ratio": (
                forward_backward_byte_ratio
            ),

            # Protocol
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "icmp_packets": self.icmp_packets,

            # TCP behavior
            "tcp_syn": self.tcp_syn,
            "tcp_ack": self.tcp_ack,
            "tcp_rst": self.tcp_rst,

            "syn_rate": syn_rate,
            "rst_rate": rst_rate,

            # Diversity
            "unique_sources": len(self.source_ips),
            "unique_destinations": len(self.destination_ips),

            "unique_destination_ports": (
                len(self.destination_ports)
            ),

            "active_flows": len(self.flows),
        }


class WindowManager:

    def __init__(self, window_seconds: float = 1.0):

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than 0"
            )

        self.window_seconds = window_seconds

        # The first packet establishes the timeline.
        self.current = None

    def _new_window(self, start_time: float):

        self.current = ObservationWindow(
            window_start=start_time
        )

    def add_packet(self, timestamp: float, **packet_data):

        # --------------------------------------------------
        # First packet
        # --------------------------------------------------

        if self.current is None:

            self._new_window(timestamp)

            self.current.add_packet(**packet_data)

            return None

        # --------------------------------------------------
        # Determine current window end
        # --------------------------------------------------

        window_end = (
            self.current.window_start
            + self.window_seconds
        )

        # --------------------------------------------------
        # Packet belongs to current window
        # --------------------------------------------------

        if timestamp < window_end:

            self.current.add_packet(**packet_data)

            return None

        # --------------------------------------------------
        # Current window is complete
        # --------------------------------------------------

        features = self.current.to_features(
            self.window_seconds
        )

        # --------------------------------------------------
        # Determine which window the new packet belongs to
        # --------------------------------------------------

        elapsed = timestamp - self.current.window_start

        windows_passed = int(
            elapsed // self.window_seconds
        )

        new_start = (
            self.current.window_start
            + windows_passed * self.window_seconds
        )

        self._new_window(new_start)

        self.current.add_packet(**packet_data)

        return features
