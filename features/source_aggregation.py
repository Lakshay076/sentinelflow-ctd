from collections import defaultdict


class SourceAggregator:
    """
    Aggregates network behavior separately for each source IP
    inside one observation window.

    This allows CTD to answer:
        "What is this particular source doing?"
    """

    def __init__(self):
        self.sources = defaultdict(self._new_source)

    @staticmethod
    def _new_source():
        return {
            "packets": 0,
            "bytes": 0,
            "bytes_received": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "tcp_syn": 0,
            "tcp_ack": 0,
            "tcp_rst": 0,
            "destination_ips": set(),
            "destination_ports": set(),
            "flows": set(),
        }

    def add_packet(
        self,
        src_ip,
        dst_ip,
        protocol,
        packet_bytes,
        src_port=0,
        dst_port=0,
        tcp_syn=False,
        tcp_ack=False,
        tcp_rst=False,
        initiator_ip=None,
        responder_ip=None,
    ):
        source = self.sources[src_ip]
        dest = self.sources[dst_ip]

        source["packets"] += 1
        source["bytes"] += packet_bytes
        dest["bytes_received"] += packet_bytes

        # Connection-attempt features are attributed to the
        # flow initiator, not blindly to packet src_ip.
        #
        # This is critical for passive monitoring:
        #   initiator -> SYN     = connection attempt
        #   responder -> SYN+ACK = response, not a new attempt
        #
        # General packet/byte statistics above remain packet-direction
        # based so traffic and transfer analytics are preserved.
        connection_source_ip = initiator_ip or src_ip
        connection_source = self.sources[connection_source_ip]

        if tcp_syn and initiator_ip == src_ip:
            connection_source["destination_ips"].add(dst_ip)

            if dst_port:
                connection_source["destination_ports"].add(dst_port)

        protocol = protocol.upper()

        if protocol == "TCP":
            source["tcp_packets"] += 1

            if tcp_syn and initiator_ip == src_ip:
                connection_source["tcp_syn"] += 1

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

        # Count the observed flow under its initiator for
        # connection-rate / reconnaissance features.
        if initiator_ip == src_ip:
            connection_source["flows"].add(flow_id)
        elif initiator_ip is None:
            # Non-TCP or otherwise role-less traffic retains the
            # historical packet-direction behavior.
            source["flows"].add(flow_id)

    def get_features(self, duration):
        duration = max(duration, 0.000001)

        results = {}

        for src_ip, source in self.sources.items():
            packets = source["packets"]
            flows = len(source["flows"])
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
                "icmp_packets": source["icmp_packets"],
                "tcp_syn": source["tcp_syn"],
                "tcp_ack": source["tcp_ack"],
                "tcp_rst": source["tcp_rst"],
                "syn_rate": source["tcp_syn"] / duration,
                "rst_rate": source["tcp_rst"] / duration,
                "unique_destinations": len(source["destination_ips"]),
                "unique_destination_ports": len(source["destination_ports"]),
                "active_flows": flows,
                "flows_per_second": flows / duration,
                "syn_packet_ratio": source["tcp_syn"] / max(packets, 1),
                "rst_packet_ratio": source["tcp_rst"] / max(packets, 1),
                "ports_per_destination": (
                    len(source["destination_ports"])
                    / max(len(source["destination_ips"]), 1)
                ),
            }

        return results

    def reset(self):
        self.sources.clear()
