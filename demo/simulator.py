import random
import string
import time

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw
from scapy.layers.tls.all import TLS, TLSClientHello

import collector.packet_collector as collector
from flow.flow_engine import FlowEngine
from features.window import WindowManager
from features.source_aggregation import SourceAggregator
from features.behavior_window import BehaviorWindow
from features.beacon_tracker import BeaconTracker
from features.dns_tracker import DNSTracker
from features.tls_tracker import TLSTracker
from alerts.alert_store import AlertStore


ATTACK_TYPES = {
    "PORT_SCAN",
    "SYN_FLOOD",
    "C2_BEACONING",
    "DGA_DNS_TUNNELLING",
    "TLS_METADATA_ANOMALY",
    "DATA_EXFILTRATION",
}


def reset_demo_pipeline():
    """
    Reset only the in-memory streaming state used by the demo.

    Alert persistence is intentionally NOT reset. Alerts produced by
    the simulator still go through the normal AlertManager/PostgreSQL
    path and remain visible in the dashboard.
    """
    collector.flow_engine = FlowEngine(timeout=60)
    collector.window_manager = WindowManager(window_seconds=1.0)
    collector.source_aggregator = SourceAggregator()
    collector.behavior_window = BehaviorWindow(window_seconds=10.0)
    collector.beacon_tracker = BeaconTracker(window_seconds=300.0)
    collector.dns_tracker = DNSTracker(window_seconds=30.0)
    collector.tls_tracker = TLSTracker(window_seconds=300.0)


def tcp_packet(src, dst, sport, dport, flags="S", payload=None):
    packet = IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
    )

    if payload:
        packet = packet / Raw(load=payload)

    return packet


def port_scan_packets(src, dst, base):
    packets = []

    for index, port in enumerate(range(20, 45)):
        packets.append(
            tcp_packet(
                src,
                dst,
                30000 + index,
                port,
                "S",
            )
        )
        packets[-1].time = base + (index * 0.02)

    return packets


def syn_flood_packets(src, dst, base):
    packets = []

    for index in range(500):
        packets.append(
            tcp_packet(
                src,
                dst,
                20000 + index,
                80,
                "S",
            )
        )
        packets[-1].time = base + (index * 0.001)

    return packets


def c2_beacon_packets(src, dst, base):
    packets = []

    for index in range(5):
        packets.append(
            tcp_packet(
                src,
                dst,
                41000 + index,
                8080,
                "S",
            )
        )
        packets[-1].time = base + (index * 5.0)

    return packets


def dga_packets(src, dst, base):
    tokens = [
        "x7k2m9q4v8z1p6r3t5n0a8f2k7m4q9v1",
        "q9v3x7m1k8z4p2r6t0n5b6r1x8m3q7v2",
        "m4z8q1x7v3k9p2r6n0t5c9v2k7x4m1q8",
        "r6n2v9x4k1z8q3m7p0t5d3q8m2v7x1k9",
        "z3q8m1v7x4k9r2n6p0t5f8x3q7m1v4k9",
        "k7x2r9m4v1z8q3n6p0t5g2m8q4v1x7r9",
        "v4n8q1m7x3z9k2r6p0t5h7r2x8m4q1v9",
        "x9m3q7v1k4z8r2n6p0t5j4q9v2m7x1k8",
        "q2v8x4m1z7k9r3n6p0t5k8x2m9q4v1r7",
        "m8r3q1v7x4z9k2n6p0t5l3v8q1x6m4r9",
    ]

    packets = []

    for index, token in enumerate(tokens):
        domain = f"{token}.example.com"

        packet = (
            IP(src=src, dst=dst)
            / UDP(sport=53000 + index, dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain),
            )
        )

        packet.time = base + (index * 0.05)
        packets.append(packet)

    return packets


def tls_anomaly_packets(src, dst, base):
    packets = []

    for index in range(3):
        packet = (
            IP(src=src, dst=dst)
            / TCP(
                sport=44000 + index,
                dport=8443,
                flags="PA",
            )
            / TLS(
                msg=[
                    TLSClientHello(
                        version=0x0303,
                        ciphers=[0x002F],
                    )
                ]
            )
        )

        packet.time = base + (index * 0.2)
        packets.append(packet)

    return packets


def exfil_packets(src, dst, base):
    payload = b"A" * 30000
    packets = []

    for index in range(20):
        packet = tcp_packet(
            src,
            dst,
            45000,
            9000,
            "PA",
            payload,
        )

        packet.time = base + (index * 0.04)
        packets.append(packet)

    return packets


def build_packets(attack_type, source_ip, target_ip, base):
    if attack_type == "PORT_SCAN":
        return port_scan_packets(source_ip, target_ip, base)

    if attack_type == "SYN_FLOOD":
        return syn_flood_packets(source_ip, target_ip, base)

    if attack_type == "C2_BEACONING":
        return c2_beacon_packets(source_ip, target_ip, base)

    if attack_type == "DGA_DNS_TUNNELLING":
        return dga_packets(source_ip, target_ip, base)

    if attack_type == "TLS_METADATA_ANOMALY":
        return tls_anomaly_packets(source_ip, target_ip, base)

    if attack_type == "DATA_EXFILTRATION":
        return exfil_packets(source_ip, target_ip, base)

    raise ValueError(
        f"Unsupported demo attack type: {attack_type}"
    )


def run_demo_simulation(
    attack_type,
    source_ip="10.10.10.10",
    target_ip="10.10.10.20",
):
    """
    Generate synthetic packet metadata and feed it through MONI's
    existing collector pipeline.

    No packets are transmitted to the network.
    """

    attack_type = attack_type.upper()

    if attack_type not in ATTACK_TYPES:
        raise ValueError(
            f"Unsupported demo attack type: {attack_type}"
        )

    reset_demo_pipeline()

    base = time.time()
    packets = build_packets(
        attack_type,
        source_ip,
        target_ip,
        base,
    )

    for packet in packets:
        collector.process_packet(packet)

    # Force the final 1-second observation window to close.
    final_time = float(packets[-1].time) + 1.1

    boundary = tcp_packet(
        source_ip,
        target_ip,
        49000,
        1,
        "A",
    )
    boundary.time = final_time

    collector.process_packet(boundary)

    store = AlertStore()
    alert = store.find_active(
        source_ip=source_ip,
        attack_type=attack_type,
    )

    return {
        "status": "completed",
        "attack_type": attack_type,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "synthetic_packets": len(packets),
        "detected": alert is not None,
        "alert": alert.to_dict() if alert else None,
    }
