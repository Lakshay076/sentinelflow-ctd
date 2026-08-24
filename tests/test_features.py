from collector.packet_record import PacketRecord
from flow.flow_engine import FlowEngine
from features.flow_features import extract_features


engine = FlowEngine()


packets = [

    PacketRecord(
        timestamp=1000.000,
        src_ip="10.10.10.10",
        dst_ip="10.10.10.20",
        src_port=50000,
        dst_port=9000,
        protocol="TCP",
        packet_length=100
    ),

    PacketRecord(
        timestamp=1001.000,
        src_ip="10.10.10.20",
        dst_ip="10.10.10.10",
        src_port=9000,
        dst_port=50000,
        protocol="TCP",
        packet_length=200
    ),

    PacketRecord(
        timestamp=1002.000,
        src_ip="10.10.10.10",
        dst_ip="10.10.10.20",
        src_port=50000,
        dst_port=9000,
        protocol="TCP",
        packet_length=300
    )
]


for packet in packets:

    flow = engine.process_packet(packet)


features = extract_features(flow)


print("Flow features")
print("----------------------------")

print("Duration:",
      features.duration)

print("Total packets:",
      features.total_packets)

print("Total bytes:",
      features.total_bytes)

print("Forward packets:",
      features.forward_packets)

print("Backward packets:",
      features.backward_packets)

print("Forward bytes:",
      features.forward_bytes)

print("Backward bytes:",
      features.backward_bytes)

print("Packets/sec:",
      features.packets_per_second)

print("Bytes/sec:",
      features.bytes_per_second)

print("Forward/backward byte ratio:",
      features.forward_backward_byte_ratio)
