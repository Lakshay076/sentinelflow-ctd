from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS

from collector.packet_record import PacketRecord
from flow.flow_engine import FlowEngine
from features.window import WindowManager
from features.security_features import calculate_security_features
from features.source_aggregation import SourceAggregator
from features.feature_context import FeatureContext
from detectors.detector_engine import DetectorEngine
from features.behavior_window import BehaviorWindow
from alerts.alert_manager import AlertManager

# STAGE 2, 3, 4 ADDITIONS:
from features.beacon_tracker import BeaconTracker
from features.dns_tracker import DNSTracker
from features.tls_tracker import TLSTracker
from features.tls_parser import parse_client_hello, compute_ja3

import os
import sys
import threading
import time

INTERFACE = os.getenv("CTD_INTERFACE", "en0")

flow_engine = FlowEngine(timeout=60)

# Network-wide observation window.
# A completed feature vector is produced every 1 second.
window_manager = WindowManager(window_seconds=1.0)
source_aggregator = SourceAggregator()

# use_ml=True will use the trained ML model if one exists
# (inference/model.joblib). If it doesn't exist yet, the ML
# detector safely does nothing until you run:
#   python -m inference.train_model
detector_engine = DetectorEngine(use_ml=True)

behavior_window = BehaviorWindow(
    window_seconds=10.0
)
alert_manager = AlertManager(
    resolve_after=300.0
)

# STAGE 2: tracks connection timing per (source, destination)
# over a 5-minute rolling window, to spot regular "check-ins".
beacon_tracker = BeaconTracker(window_seconds=300.0)

# STAGE 3: tracks DNS query names per source over a 30-second
# rolling window, to spot DGA / DNS tunnelling.
dns_tracker = DNSTracker(window_seconds=30.0)

# STAGE 4: tracks TLS ClientHello metadata per source over a
# 5-minute rolling window, to spot non-browser-like TLS clients.
tls_tracker = TLSTracker(window_seconds=300.0)

pipeline_lock = threading.Lock()


def evaluate_window(window_features, source_features, timestamp):
    security_features = calculate_security_features(window_features)
    behavior_features = behavior_window.get_source_features(current_timestamp=timestamp)
    beacon_features = beacon_tracker.get_features(current_timestamp=timestamp)
    dns_features = dns_tracker.get_features(current_timestamp=timestamp)
    tls_features = tls_tracker.get_features(current_timestamp=timestamp)

    context = FeatureContext(
        network=window_features,
        security=security_features,
        sources=source_features,
        behavior=behavior_features,
        beacon=beacon_features,
        dns=dns_features,
        tls=tls_features,
    )

    detections = detector_engine.analyze_context(context)
    for source_ip, results in detections.items():
        alert_manager.process(
            source_ip=source_ip,
            detections=results,
            timestamp=timestamp,
        )

    resolved_alerts = alert_manager.resolve_stale(timestamp=timestamp)

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

    print("\nActive Alerts")
    print("-" * 70)
    for alert in alert_manager.active_alerts():
        print(f"#{alert.alert_id} {alert.attack_type:12} {alert.source_ip:15} {alert.status:8}")

    source_aggregator.reset()


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

    with pipeline_lock:
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            tcp_flags = str(flags)
            tcp_syn = "S" in flags
            tcp_ack = "A" in flags
            tcp_rst = "R" in flags

            try:
                tcp_payload = bytes(packet[TCP].payload)
                if tcp_payload:
                    parsed_hello = parse_client_hello(tcp_payload)
                    if parsed_hello is not None:
                        _, ja3_hash = compute_ja3(parsed_hello)
                        tls_tracker.add_client_hello(
                            timestamp=timestamp,
                            src_ip=ip.src,
                            dst_ip=ip.dst,
                            ja3_hash=ja3_hash,
                            cipher_count=len(parsed_hello["cipher_suites"]),
                            extension_count=len(parsed_hello["extensions"]),
                            has_sni=(parsed_hello["sni"] is not None),
                        )
            except Exception:
                pass

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            try:
                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    if dns_layer.qr == 0 and dns_layer.qd:
                        try:
                            first_query = dns_layer.qd[0]
                        except (TypeError, IndexError):
                            first_query = dns_layer.qd

                        raw_name = first_query.qname
                        if isinstance(raw_name, bytes):
                            domain = raw_name.decode("utf-8", errors="ignore")
                        else:
                            domain = str(raw_name)

                        dns_tracker.add_query(
                            timestamp=timestamp,
                            src_ip=ip.src,
                            domain=domain,
                        )
            except Exception:
                pass

        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = str(ip.proto)

        record = PacketRecord(
            timestamp=timestamp,
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=str(protocol),
            packet_length=len(packet),
            tcp_flags=tcp_flags,
        )

        is_new_flow = flow_engine.is_new_flow(
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=src_port or 0,
            dst_port=dst_port or 0,
            protocol=str(protocol),
        )

        flow = flow_engine.process_packet(record)

        if is_new_flow:
            beacon_tracker.record_new_flow(
                timestamp=timestamp,
                src_ip=ip.src,
                dst_ip=ip.dst,
            )

        packet_data = dict(
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

        # Check whether this packet closes the current
        # fixed observation window BEFORE adding it to
        # the source-level aggregator.
        window_features = window_manager.add_packet(
            timestamp=timestamp,
            **packet_data,
        )

        if window_features:
            source_features = source_aggregator.get_features(
                window_features["window_duration"]
            )

            source_aggregator.reset()

            evaluate_window(
                window_features,
                source_features,
                timestamp,
            )

        source_aggregator.add_packet(**packet_data)

        behavior_window.add_packet(
            timestamp=timestamp,
            **packet_data,
        )


def background_flusher():
    while True:
        time.sleep(0.5)
        now = time.time()

        with pipeline_lock:

            # Resolve alerts independently of incoming traffic.
            # This ensures alerts become RESOLVED after 5 minutes
            # even when the monitored interface becomes completely idle.
            alert_manager.resolve_stale(
                timestamp=now
            )

            features = window_manager.flush_if_ready(now)

            if features:
                source_features = source_aggregator.get_features(
                    features["window_duration"]
                )

                source_aggregator.reset()

                evaluate_window(
                    features,
                    source_features,
                    now,
                )

def main():
    global INTERFACE
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        INTERFACE = sys.argv[1]
    elif "--interface" in sys.argv:
        idx = sys.argv.index("--interface")
        if idx + 1 < len(sys.argv):
            INTERFACE = sys.argv[idx + 1]

    print("=" * 70)
    print("CTD — LIVE FLOW + WINDOW FEATURE COLLECTOR")
    print("=" * 70)
    print(f"Interface : {INTERFACE}")
    print("Mode      : READ-ONLY")
    print("Payload   : NOT INSPECTED (metadata only)")
    print("Flow      : BIDIRECTIONAL")
    print("Window    : 1 second")
    print("Detectors : port scan, SYN flood, exfiltration,")
    print("            C2 beaconing, DGA/DNS tunnelling,")
    print("            TLS metadata anomaly, ML anomaly")
    print("Status    : Listening...")
    print("=" * 70)

    flusher_thread = threading.Thread(target=background_flusher, daemon=True)
    flusher_thread.start()

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
