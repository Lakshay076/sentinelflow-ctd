from collector.packet_record import PacketRecord
from flow.flow_engine import FlowEngine

from features.streaming_features import (
    StreamingFeatureEngine
)


flow_engine = FlowEngine()

feature_engine = StreamingFeatureEngine()


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
    ),

]


for i, packet in enumerate(packets, start=1):

    flow = flow_engine.process_packet(packet)

    flow_id = "flow-1"

    features = feature_engine.extract(
        flow_id,
        flow
    )

    print()
    print(f"UPDATE {i}")
    print("----------------------------")

    print(
        "Packets:",
        features.total_packets
    )

    print(
        "Bytes:",
        features.total_bytes
    )

    print(
        "Forward packets:",
        features.forward_packets
    )

    print(
        "Backward packets:",
        features.backward_packets
    )

    print(
        "Packets/sec:",
        round(
            features.packets_per_second,
            3
        )
    )

    print(
        "Bytes/sec:",
        round(
            features.bytes_per_second,
            3
        )
    )


print()
print(
    "Total feature updates:",
    feature_engine.feature_updates
)
