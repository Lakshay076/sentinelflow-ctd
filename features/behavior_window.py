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
        initiator_ip: str = None,
        responder_ip: str = None,
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
            initiator_ip,
            responder_ip,
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
                "bytes_received": 0,
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
                initiator_ip,
                _responder_ip,
            ) = event

            source = sources[src_ip]
            dest = sources[dst_ip]

            source["packets"] += 1
            source["bytes"] += packet_bytes
            dest["bytes_received"] += packet_bytes

            # Attribute connection-initiation and scan fan-out metrics to the
            # initiator (matching SourceAggregator), while keeping byte/packet
            # totals packet-direction based. Responders sending SYN+ACK/ACK/RST
            # must never inherit connection or scan-port metrics.
            connection_source_ip = initiator_ip or src_ip
            connection_source = sources[connection_source_ip]
            is_initiator_or_unassigned = initiator_ip is None or initiator_ip == src_ip

            if protocol == "TCP":

                source["tcp_packets"] += 1

                if tcp_syn and not tcp_ack and is_initiator_or_unassigned:
                    connection_source["tcp_syn"] += 1

                if tcp_ack:
                    source["tcp_ack"] += 1

                if tcp_rst:
                    source["tcp_rst"] += 1

                if initiator_ip == src_ip or (initiator_ip is None and not tcp_rst):
                    connection_source["destinations"].add(dst_ip)
                    if dst_port:
                        connection_source["destination_ports"].add(dst_port)

            elif protocol == "UDP":

                source["udp_packets"] += 1
                source["destinations"].add(dst_ip)
                if dst_port:
                    source["destination_ports"].add(dst_port)

            elif protocol == "ICMP":

                source["icmp_packets"] += 1
                source["destinations"].add(dst_ip)

            flow_id = (
                f"{src_ip}:{src_port}"
                f"->{dst_ip}:{dst_port}"
                f"/{protocol}"
            )

            if initiator_ip == src_ip:
                connection_source["flows"].add(flow_id)
            elif initiator_ip is None and not (protocol == "TCP" and tcp_rst and not tcp_syn):
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
            bytes_sent = source["bytes"]
            bytes_received = source["bytes_received"]

            if bytes_received > 0:
                ratio = bytes_sent / bytes_received
            elif bytes_sent > 0:
                ratio = float(bytes_sent)
            else:
                ratio = 1.0

            results[src_ip] = {
                "packets": packets,
                "bytes": bytes_sent,
                "bytes_received": bytes_received,
                "outbound_inbound_ratio": ratio,
                "packets_per_second": packets / duration,
                "bytes_per_second": bytes_sent / duration,
                "tcp_packets": source["tcp_packets"],
                "udp_packets": source["udp_packets"],
                "udp_rate": source["udp_packets"] / duration,
                "udp_packet_ratio": (
                    source["udp_packets"] / max(packets, 1)
                ),
                "icmp_packets": source["icmp_packets"],
                "tcp_syn": source["tcp_syn"],
                "tcp_ack": source["tcp_ack"],
                "tcp_rst": source["tcp_rst"],
                "syn_rate": source["tcp_syn"] / duration,
                "rst_rate": source["tcp_rst"] / duration,
                "unique_destinations": destinations,
                "unique_destination_ports": ports,
                "active_flows": flows,
                "flows_per_second": flows / duration,
                "syn_packet_ratio": (
                    source["tcp_syn"] / max(packets, 1)
                ),
                "rst_packet_ratio": (
                    source["tcp_rst"] / max(packets, 1)
                ),
                "ports_per_destination": (
                    ports / max(destinations, 1)
                ),
            }

        return results

    def size(self):
        """Return number of events currently stored."""

        return len(self.events)

    def reset(self):
        """Clear the rolling behavioral state."""

        self.events.clear()
