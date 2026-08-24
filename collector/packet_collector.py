from scapy.all import sniff, IP, TCP, UDP, ICMP

from collector.packet_record import PacketRecord
from flow.flow_engine import FlowEngine
from features.window import WindowManager
from features.security_features import calculate_security_features
from features.source_aggregation import SourceAggregator
from features.feature_context import FeatureContext
from detectors.detector_engine import DetectorEngine
from features.behavior_window import BehaviorWindow
from alerts.alert_manager import AlertManager

INTERFACE = "enp0s8"

flow_engine = FlowEngine(timeout=60)

# Network-wide observation window.
# A completed feature vector is produced every 1 second.
window_manager = WindowManager(window_seconds=1.0)
source_aggregator = SourceAggregator()
detector_engine = DetectorEngine()
behavior_window = BehaviorWindow(
    window_seconds=10.0
)
alert_manager = AlertManager(
    resolve_after=10.0
)

def process_packet(packet):

    if IP not in packet:
        return

    ip = packet[IP]

    timestamp = float(packet.time)

    src_port = None
    dst_port = None
    protocol = None
    tcp_flags = None

    tcp_syn = False
    tcp_ack = False
    tcp_rst = False

    # -------------------------
    # TCP
    # -------------------------

    if TCP in packet:

        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        flags = packet[TCP].flags
        tcp_flags = str(flags)

        tcp_syn = "S" in flags
        tcp_ack = "A" in flags
        tcp_rst = "R" in flags

    # -------------------------
    # UDP
    # -------------------------

    elif UDP in packet:

        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # -------------------------
    # ICMP
    # -------------------------

    elif ICMP in packet:

        protocol = "ICMP"

    # -------------------------
    # Other IPv4 protocols
    # -------------------------

    else:

        protocol = str(ip.proto)

    # -------------------------
    # Create PacketRecord
    # -------------------------

    record = PacketRecord(
        timestamp=timestamp,
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=str(protocol),
        packet_length=len(packet),
        tcp_flags=tcp_flags
    )

    # =========================================================
    # PIPELINE 1 — FLOW ENGINE
    # =========================================================

    flow = flow_engine.process_packet(record)

    print(
        f"[FLOW] "
        f"{flow.protocol} "
        f"{flow.src_ip}:{flow.src_port} -> "
        f"{flow.dst_ip}:{flow.dst_port} | "
        f"packets={flow.packets} "
        f"bytes={flow.bytes} "
        f"fwd={flow.forward_packets} "
        f"bwd={flow.backward_packets} "
        f"duration={flow.duration():.3f}s"
    )

    # =========================================================
    # PIPELINE 2 — OBSERVATION WINDOW
    # =========================================================

    window_features = window_manager.add_packet(
        timestamp=timestamp,
        src_ip=ip.src,
        dst_ip=ip.dst,
        protocol=protocol,
        packet_bytes=len(packet),
        src_port=src_port or 0,
        dst_port=dst_port or 0,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
        tcp_rst=tcp_rst,
    )
    # =========================================================
    # PIPELINE 3 — PER-SOURCE AGGREGATION
    # =========================================================

    source_aggregator.add_packet(
        src_ip=ip.src,
        dst_ip=ip.dst,
        protocol=protocol,
        packet_bytes=len(packet),
        src_port=src_port or 0,
        dst_port=dst_port or 0,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
        tcp_rst=tcp_rst,
    )

    # =========================================================
    # PIPELINE 4 — ROLLING BEHAVIOR WINDOW
    # =========================================================

    behavior_window.add_packet(
        timestamp=timestamp,
        src_ip=ip.src,
        dst_ip=ip.dst,
        protocol=protocol,
        packet_bytes=len(packet),
        src_port=src_port or 0,
        dst_port=dst_port or 0,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
        tcp_rst=tcp_rst,
    )

    # A value is returned only when the 1-second
    # observation window has completed.
    if window_features:
        # =========================================================
        # PIPELINE 3 — SECURITY FEATURES
        # =========================================================

        security_features = calculate_security_features(
            window_features
        )
        source_features = source_aggregator.get_features(
            window_features["window_duration"]
        )
        behavior_features = (
            behavior_window.get_source_features(
                current_timestamp=timestamp
            )
        )
        context = FeatureContext(
            network=window_features,
            security=security_features,
            sources=source_features,
            behavior=behavior_features,
        )

        detections = detector_engine.analyze_context(context)
        for source_ip, results in detections.items():
            alert_manager.process(
                source_ip=source_ip,
                detections=results,
                timestamp=timestamp,
        )

        resolved_alerts = alert_manager.resolve_stale(
            timestamp=timestamp
        )

        print()
        print("=" * 70)
        print("[WINDOW COMPLETE]")
        print("=" * 70)

        print("\nBasic Features")
        print("-" * 70)

        for key, value in window_features.items():

            if isinstance(value, float):
                print(f"{key:30} : {value:.3f}")
            else:
                print(f"{key:30} : {value}")

        print("\nSecurity Features")
        print("-" * 70)

        for key, value in security_features.items():

            if isinstance(value, float):
                print(f"{key:30} : {value:.4f}")
            else:
                print(f"{key:30} : {value}")

        print("=" * 70)
        print()
        print("\nPer-Source Features")
        print("-" * 70)

        for source_ip, features in source_features.items():

            print(f"\nSource: {source_ip}")

            for key, value in features.items():

                if isinstance(value, float):
                    print(f"{key:30} : {value:.4f}")
                else:
                    print(f"{key:30} : {value}")

        print("\nDetections")
        print("-" * 70)

        any_detection = False

        for source_ip, results in detections.items():

            for result in results:

                any_detection = True

                print()
                print("=" * 70)
                print("🚨 ALERT")
                print("=" * 70)
                print(f"Source      : {source_ip}")
                print(f"Attack      : {result.attack_type}")
                print(f"Severity    : {result.severity}")
                print(f"Score       : {result.score}")
                print(f"Confidence  : {result.confidence:.2f}")

                print("Reasons:")

                for reason in result.reasons:
                    print(f"  - {reason}")

        if not any_detection:
            print("No detections")

        print("\nAlert History")
        print("-" * 70)

        for alert in alert_manager.history():

            print(
                f"#{alert.alert_id} "
                f"{alert.attack_type:12} "
                f"{alert.source_ip:15} "
                f"{alert.status:8} "
                f"events={alert.event_count}"
            )
        print("\nActive Alerts")
        print("-" * 70)

        for alert in alert_manager.active_alerts():

            print(
                f"#{alert.alert_id} "
                f"{alert.attack_type:12} "
                f"{alert.source_ip:15} "
                f"{alert.status:8}"
            )


        print("\nRolling 10-Second Behavior")
        print("-" * 70)

        for source_ip, features in behavior_features.items():

            print(f"\nSource: {source_ip}")

            for key, value in features.items():

                if isinstance(value, float):
                    print(
                        f"{key:30} : {value:.4f}"
                    )
                else:
                    print(
                        f"{key:30} : {value}"
                    )
        source_aggregator.reset()


def main():

    print("=" * 70)
    print("CTD — LIVE FLOW + WINDOW FEATURE COLLECTOR")
    print("=" * 70)
    print(f"Interface : {INTERFACE}")
    print("Mode      : READ-ONLY")
    print("Payload   : NOT INSPECTED")
    print("Flow      : BIDIRECTIONAL")
    print("Window    : 1 second")
    print("Status    : Listening...")
    print("=" * 70)

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    main()
