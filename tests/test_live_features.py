from scapy.all import sniff

from collector.packet_record import PacketRecord
from flow.flow_engine import FlowEngine
from features.streaming_features import StreamingFeatureEngine


INTERFACE = "enp0s8"

flow_engine = FlowEngine()
feature_engine = StreamingFeatureEngine()


def process_packet(packet):

    if not packet.haslayer("IP"):
        return

    ip = packet["IP"]

    protocol = "OTHER"

    if packet.haslayer("TCP"):
        protocol = "TCP"

    elif packet.haslayer("UDP"):
        protocol = "UDP"

    elif packet.haslayer("ICMP"):
        protocol = "ICMP"

    src_port = 0
    dst_port = 0

    if packet.haslayer("TCP"):
        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport

    elif packet.haslayer("UDP"):
        src_port = packet["UDP"].sport
        dst_port = packet["UDP"].dport

    record = PacketRecord(
        timestamp=float(packet.time),
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_length=len(packet)
    )

    flow = flow_engine.process_packet(record)

    flow_id = (
        f"{flow.src_ip}:{flow.src_port}"
        f"->"
        f"{flow.dst_ip}:{flow.dst_port}"
    )

    features = feature_engine.extract(
        flow_id,
        flow
    )

    print(
        f"[FEATURE] "
        f"{protocol} "
        f"{flow.src_ip}:{flow.src_port} -> "
        f"{flow.dst_ip}:{flow.dst_port} | "
        f"packets={features.total_packets} "
        f"bytes={features.total_bytes} "
        f"pps={features.packets_per_second:.2f} "
        f"bps={features.bytes_per_second:.2f}"
    )


print("=" * 70)
print("CTD — LIVE FEATURE ENGINE")
print("=" * 70)
print(f"Interface : {INTERFACE}")
print("Payload   : NOT INSPECTED")
print("Status    : Listening...")
print("=" * 70)


sniff(
    iface=INTERFACE,
    prn=process_packet,
    store=False
)
