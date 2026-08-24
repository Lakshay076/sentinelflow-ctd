from collections import defaultdict, deque


class BehaviorWindow:
    """
    Rolling behavioral window.

    Keeps packet metadata for the most recent N seconds.
    Old observations automatically expire.

    This is a streaming component:
        packet arrives
            -> add observation
            -> remove expired observations
            -> calculate current behavior
    """

    def __init__(self, window_seconds: float = 10.0):

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than 0"
            )

        self.window_seconds = window_seconds

        # Each entry contains:
        #
        # (timestamp, source_ip, dst_ip, protocol,
        #  packet_bytes, src_port, dst_port,
        #  tcp_syn, tcp_ack, tcp_rst)
        #
        self.events = deque()

    def add_packet(
        self,
        timestamp: float,
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
        Add one packet and remove observations
        older than the rolling window.
        """

        event = (
            timestamp,
            src_ip,
            dst_ip,
            protocol.upper(),
            packet_bytes,
            src_port,
            dst_port,
            tcp_syn,
            tcp_ack,
            tcp_rst,
        )

        self.events.append(event)

        self._expire(timestamp)

    def _expire(self, current_timestamp: float):
        """
        Remove events outside the rolling time window.
        """

        cutoff = current_timestamp - self.window_seconds

        while self.events:

            oldest_timestamp = self.events[0][0]

            if oldest_timestamp >= cutoff:
                break

            self.events.popleft()

    def get_source_features(
        self,
        current_timestamp: float
    ):
        """
        Calculate behavioral features for every source
        currently present in the rolling window.
        """

        self._expire(current_timestamp)

        sources = defaultdict(
            lambda: {
                "packets": 0,
                "bytes": 0,
                "tcp_packets": 0,
                "udp_packets": 0,
                "icmp_packets": 0,
                "tcp_syn": 0,
                "tcp_ack": 0,
                "tcp_rst": 0,
                "destinations": set(),
                "destination_ports": set(),
                "flows": set(),
            }
        )

        for event in self.events:

            (
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                packet_bytes,
                src_port,
                dst_port,
                tcp_syn,
                tcp_ack,
                tcp_rst,
            ) = event

            source = sources[src_ip]

            source["packets"] += 1
            source["bytes"] += packet_bytes

            source["destinations"].add(dst_ip)

            if dst_port:
                source["destination_ports"].add(
                    dst_port
                )

            if protocol == "TCP":

                source["tcp_packets"] += 1

                if tcp_syn:
                    source["tcp_syn"] += 1

                if tcp_ack:
                    source["tcp_ack"] += 1

                if tcp_rst:
                    source["tcp_rst"] += 1

            elif protocol == "UDP":

                source["udp_packets"] += 1

            elif protocol == "ICMP":

                source["icmp_packets"] += 1

            flow_id = (
                f"{src_ip}:{src_port}"
                f"->{dst_ip}:{dst_port}"
                f"/{protocol}"
            )

            source["flows"].add(flow_id)

        return self._build_features(
            sources
        )

    def _build_features(self, sources):

        duration = self.window_seconds

        results = {}

        for src_ip, source in sources.items():

            packets = source["packets"]
            flows = len(source["flows"])
            destinations = len(
                source["destinations"]
            )
            ports = len(
                source["destination_ports"]
            )

            results[src_ip] = {

                "packets": packets,

                "bytes":
                    source["bytes"],

                "packets_per_second":
                    packets / duration,

                "bytes_per_second":
                    source["bytes"] / duration,

                "tcp_packets":
                    source["tcp_packets"],

                "udp_packets":
                    source["udp_packets"],

                "icmp_packets":
                    source["icmp_packets"],

                "tcp_syn":
                    source["tcp_syn"],

                "tcp_ack":
                    source["tcp_ack"],

                "tcp_rst":
                    source["tcp_rst"],

                "unique_destinations":
                    destinations,

                "unique_destination_ports":
                    ports,

                "active_flows":
                    flows,

                "flows_per_second":
                    flows / duration,

                "syn_packet_ratio":
                    source["tcp_syn"]
                    / max(packets, 1),

                "rst_packet_ratio":
                    source["tcp_rst"]
                    / max(packets, 1),

                "ports_per_destination":
                    ports
                    / max(destinations, 1),
            }

        return results

    def size(self):
        """Return number of events currently stored."""

        return len(self.events)

    def reset(self):
        """Clear the rolling behavioral state."""

        self.events.clear()
