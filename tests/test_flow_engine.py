from collector.packet_record import PacketRecord
from flow.flow_engine import FlowEngine


engine = FlowEngine()


packets = [

    PacketRecord(
        timestamp=1000.000,
        src_ip="10.10.10.10",
        dst_ip="10.10.10.20",
        src_port=50000,
        dst_port=9000,
        protocol="TCP",
        packet_length=74
    ),

    PacketRecord(
        timestamp=1000.001,
        src_ip="10.10.10.20",
        dst_ip="10.10.10.10",
        src_port=9000,
        dst_port=50000,
        protocol="TCP",
        packet_length=74
    ),

    PacketRecord(
        timestamp=1000.002,
        src_ip="10.10.10.10",
        dst_ip="10.10.10.20",
        src_port=50000,
        dst_port=9000,
        protocol="TCP",
        packet_length=100
    )
]


for packet in packets:
    engine.process_packet(packet)


print("Number of flows:", len(engine.flows))


for flow in engine.flows.values():

    print()
    print("Flow")
    print("---------------------------")
    print("Source:", flow.src_ip, flow.src_port)
    print("Destination:", flow.dst_ip, flow.dst_port)
    print("Protocol:", flow.protocol)
    print("Packets:", flow.packets)
    print("Bytes:", flow.bytes)
    print("Forward packets:", flow.forward_packets)
    print("Backward packets:", flow.backward_packets)
    print("Forward bytes:", flow.forward_bytes)
    print("Backward bytes:", flow.backward_bytes)
    print("Duration:", flow.duration())
