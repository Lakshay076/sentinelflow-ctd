from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS

from collector.packet_record import PacketRecord
from flow.flow_engine import FlowEngine
from features.window import WindowManager
from features.security_features import calculate_security_features
from features.source_aggregation import SourceAggregator
from features.feature_context import FeatureContext
from features.communication_context import CommunicationContext
from detectors.detector_engine import DetectorEngine
from detectors.incident_correlator import IncidentCorrelator
from features.behavior_window import BehaviorWindow
from alerts.alert_manager import AlertManager
from telemetry.live_metrics import live_metrics


# STAGE 2, 3, 4 ADDITIONS:
from features.beacon_tracker import BeaconTracker
from features.dns_tracker import DNSTracker
from features.tls_tracker import TLSTracker
from features.tls_parser import (
    parse_client_hello,
    compute_ja3,
    compute_ja4,
    parse_server_hello,
    parse_quic_packet,
)

import os
import sys
import threading
import time

INTERFACE = os.getenv("CTD_INTERFACE", "en0")


class PacketPipeline:
    """
    Self-contained streaming detection pipeline instance.

    Keeping all per-run state (flows, fixed/rolling windows, trackers,
    and alert emission tracking) inside an instance allows PCAP replays
    and controlled simulations to run in complete isolation without
    mutating or resetting a concurrently running live collector.
    """

    def __init__(self, use_ml: bool = True, record_metrics: bool = True):
        self.flow_engine = FlowEngine(timeout=60)
        self.window_manager = WindowManager(window_seconds=1.0)
        self.source_aggregator = SourceAggregator()
        self.communication_context = CommunicationContext()
        self.detector_engine = DetectorEngine(use_ml=use_ml)
        self.incident_correlator = IncidentCorrelator()
        self.behavior_window = BehaviorWindow(window_seconds=10.0)
        self.alert_manager = AlertManager(resolve_after=300.0)
        self.beacon_tracker = BeaconTracker(window_seconds=300.0)
        self.dns_tracker = DNSTracker(window_seconds=30.0)
        self.tls_tracker = TLSTracker(window_seconds=300.0)
        self.pipeline_lock = threading.Lock()
        self.record_metrics = record_metrics

        # Per-instance tracking of windows and alerts produced by this pipeline.
        self.windows_evaluated = 0
        self.emitted_alert_ids = set()
        self.alert_events_count = 0

    def reset(self):
        """Reset all in-memory streaming state for this pipeline instance."""
        with self.pipeline_lock:
            self.flow_engine.flows.clear()
            self.window_manager.current = None
            self.source_aggregator.reset()
            self.communication_context.reset()
            self.incident_correlator.reset()
            self.behavior_window.reset()
            self.beacon_tracker.reset()
            self.dns_tracker.reset()
            self.tls_tracker.reset()
            self.windows_evaluated = 0
            self.emitted_alert_ids.clear()
            self.alert_events_count = 0

    def evaluate_window(
        self,
        window_features,
        source_features,
        timestamp,
        communication_features=None,
    ):
        self.windows_evaluated += 1
        security_features = calculate_security_features(window_features)
        communication_features = communication_features or []
        if self.record_metrics:
            live_metrics.add_window(
                features=window_features,
                source_features=source_features,
                timestamp=timestamp,
            )

        behavior_features = self.behavior_window.get_source_features(current_timestamp=timestamp)
        beacon_features = self.beacon_tracker.get_features(current_timestamp=timestamp)
        dns_features = self.dns_tracker.get_features(current_timestamp=timestamp)
        tls_features = self.tls_tracker.get_features(current_timestamp=timestamp)

        context = FeatureContext(
            network=window_features,
            security=security_features,
            sources=source_features,
            behavior=behavior_features,
            beacon=beacon_features,
            dns=dns_features,
            tls=tls_features,
            communication=communication_features,
        )

        detections = self.detector_engine.analyze_context(context)
        comm_context = self.detector_engine.get_communication_context(context)

        # Correlate raw detector signals into operator-facing incidents.
        # Detector thresholds, scores, and ML sensitivity remain unchanged.
        detections = self.incident_correlator.correlate(
            detections=detections,
            communication_context=comm_context,
            source_features=source_features,
            timestamp=timestamp,
        )

        for source_ip, results in detections.items():
            emitted = self.alert_manager.process(
                source_ip=source_ip,
                detections=results,
                timestamp=timestamp,
                communication_context=comm_context.get(source_ip),
            )
            for alert in emitted:
                self.emitted_alert_ids.add(alert.alert_id)
                self.alert_events_count += 1

        self.alert_manager.resolve_stale(timestamp=timestamp)

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
        for alert in self.alert_manager.active_alerts():
            print(f"#{alert.alert_id} {alert.attack_type:12} {alert.source_ip:15} {alert.status:8}")

        self.source_aggregator.reset()

    def process_packet(self, packet):
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

        with self.pipeline_lock:
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
                            ja4_full, ja4_hash = compute_ja4(parsed_hello, protocol="t")
                            self.tls_tracker.add_client_hello(
                                timestamp=timestamp,
                                src_ip=ip.src,
                                dst_ip=ip.dst,
                                ja3_hash=ja3_hash,
                                cipher_count=len(parsed_hello["cipher_suites"]),
                                extension_count=len(parsed_hello["extensions"]),
                                has_sni=(parsed_hello["sni"] is not None),
                                ja4_hash=ja4_hash,
                                ja4_full=ja4_full,
                            )

                        parsed_server = parse_server_hello(tcp_payload)
                        if parsed_server is not None:
                            self.tls_tracker.add_server_hello(
                                timestamp=timestamp,
                                server_ip=ip.src,
                                client_ip=ip.dst,
                                ja3s_hash=parsed_server["ja3s_hash"],
                                cipher_suite=parsed_server["selected_cipher"],
                                extension_count=len(parsed_server["extensions"]),
                            )

                        if dst_port in (443, 8443):
                            if dst_port in (443, 8443):
                                self.tls_tracker.add_splt_packet(
                                    timestamp=timestamp,
                                    src_ip=ip.src,
                                    packet_bytes=len(packet),
                                )
                except Exception:
                    pass

            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

                try:
                    udp_payload = bytes(packet[UDP].payload)
                    if (dst_port in (443, 8443) or src_port in (443, 8443)) and udp_payload:
                        quic_meta = parse_quic_packet(udp_payload)
                        if quic_meta:
                            self.tls_tracker.add_quic_packet(
                                timestamp=timestamp,
                                src_ip=ip.src,
                                dst_ip=ip.dst,
                                quic_meta=quic_meta,
                                packet_bytes=len(packet),
                            )
                            if dst_port in (443, 8443):
                                self.tls_tracker.add_splt_packet(
                                    timestamp=timestamp,
                                    src_ip=ip.src,
                                    packet_bytes=len(packet),
                                )
                except Exception:
                    pass

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

                            qtype = getattr(first_query, "qtype", 1)
                            self.dns_tracker.add_query(
                                timestamp=timestamp,
                                src_ip=ip.src,
                                domain=domain,
                                qtype=qtype,
                                packet_bytes=len(packet),
                            )
                        elif dns_layer.qr == 1:
                            # DNS Response observed in bidirectional capture
                            self.dns_tracker.add_response(
                                timestamp=timestamp,
                                src_ip=ip.dst,  # attribute response metadata to client IP
                                response_bytes=len(packet),
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

            is_new_flow = self.flow_engine.is_new_flow(
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=src_port or 0,
                dst_port=dst_port or 0,
                protocol=str(protocol),
            )

            flow = self.flow_engine.process_packet(record)

            # DNS request/response flows are excluded from C2 beacon
            # timing analysis. Periodic DNS queries can otherwise
            # look like beacon check-ins because they repeatedly
            # contact the same resolver at regular intervals.
            # Non-DNS TCP/UDP traffic remains eligible for C2 detection.
            if is_new_flow and src_port != 53 and dst_port != 53:
                beacon_src = flow.initiator_ip or ip.src
                beacon_dst = flow.responder_ip or ip.dst
                self.beacon_tracker.record_new_flow(
                    timestamp=timestamp,
                    src_ip=beacon_src,
                    dst_ip=beacon_dst,
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
            window_features = self.window_manager.add_packet(
                timestamp=timestamp,
                **packet_data,
            )

            if window_features:
                # The current packet belongs to the NEW window.
                # Evaluate the completed window using its own
                # communication relationships before adding this
                # boundary packet to the new context.
                source_features = self.source_aggregator.get_features(
                    window_features["window_duration"]
                )
                comm_features = self.communication_context.snapshot()

                self.source_aggregator.reset()
                self.communication_context.reset()

                self.evaluate_window(
                    window_features,
                    source_features,
                    timestamp,
                    comm_features,
                )

            # This packet belongs to the current/new window.
            self.source_aggregator.add_packet(
                **packet_data,
                initiator_ip=flow.initiator_ip,
                responder_ip=flow.responder_ip,
            )
            self.communication_context.record(flow, record)

            self.behavior_window.add_packet(
                timestamp=timestamp,
                **packet_data,
                initiator_ip=flow.initiator_ip,
                responder_ip=flow.responder_ip,
            )

    def flush_if_ready(self, timestamp: float):
        """Flush and evaluate the current observation window if its duration elapsed."""
        with self.pipeline_lock:
            self.alert_manager.resolve_stale(timestamp=timestamp)
            features = self.window_manager.flush_if_ready(timestamp)
            if features:
                source_features = self.source_aggregator.get_features(
                    features["window_duration"]
                )
                comm_features = self.communication_context.snapshot()

                self.source_aggregator.reset()
                self.communication_context.reset()

                self.evaluate_window(
                    features,
                    source_features,
                    timestamp,
                    comm_features,
                )
                return True
        return False


# Default live collector pipeline and backward-compatible module aliases.
live_pipeline = PacketPipeline(use_ml=True, record_metrics=True)

flow_engine = live_pipeline.flow_engine
window_manager = live_pipeline.window_manager
source_aggregator = live_pipeline.source_aggregator
communication_context = live_pipeline.communication_context
detector_engine = live_pipeline.detector_engine
incident_correlator = live_pipeline.incident_correlator
behavior_window = live_pipeline.behavior_window
alert_manager = live_pipeline.alert_manager
beacon_tracker = live_pipeline.beacon_tracker
dns_tracker = live_pipeline.dns_tracker
tls_tracker = live_pipeline.tls_tracker
pipeline_lock = live_pipeline.pipeline_lock


def evaluate_window(
    window_features,
    source_features,
    timestamp,
    communication_features=None,
):
    return live_pipeline.evaluate_window(
        window_features,
        source_features,
        timestamp,
        communication_features,
    )


def process_packet(packet):
    return live_pipeline.process_packet(packet)


def background_flusher():
    while True:
        time.sleep(0.5)
        live_pipeline.flush_if_ready(time.time())

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
