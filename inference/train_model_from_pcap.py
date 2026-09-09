"""
CTD -- Train ML Model on REAL Replayed Traffic

train_model.py (the original) fits the Isolation Forest on
made-up, synthetically-distributed numbers. This script instead
fits it on feature vectors produced by running an actual pcap
file through the SAME feature-extraction pipeline used at live
inference time (FlowEngine, WindowManager, SourceAggregator,
BehaviorWindow, BeaconTracker, DNSTracker, TLSTracker,
FeatureContext) -- not a separate, hand-written approximation.

Why this matters:
    If training-time features are computed differently from
    inference-time features, the model learns a baseline that
    doesn't actually match what it will be scored against live.
    Reusing the exact same modules guarantees consistency.

Expected input:
    A pcap file containing traffic you're confident is BENIGN
    ("normal") -- e.g. an hour of ordinary recorded gateway
    traffic, or the benign-labeled portion of a public dataset
    (CICIDS2017 / UNSW-NB15 / MAWILab, etc). Do NOT include
    attack traffic in this file -- Isolation Forest needs to
    learn what "normal" looks like.

Usage:
    python -m inference.train_model_from_pcap path/to/benign.pcap
    python -m inference.train_model_from_pcap path/to/benign.pcap --contamination 0.02
"""

import argparse
import json
import os

import numpy as np
from scapy.utils import PcapReader
from scapy.all import IP, TCP, UDP, ICMP, DNS
from sklearn.ensemble import IsolationForest
import joblib

from collector.packet_record import PacketRecord
from flow.flow_engine import FlowEngine
from features.window import WindowManager
from features.security_features import calculate_security_features
from features.source_aggregation import SourceAggregator
from features.feature_context import FeatureContext
from features.behavior_window import BehaviorWindow
from features.beacon_tracker import BeaconTracker
from features.dns_tracker import DNSTracker
from features.tls_tracker import TLSTracker
from features.tls_parser import parse_client_hello, compute_ja3

from inference.feature_schema import FEATURE_NAMES, features_to_vector

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.joblib")
STATS_PATH = os.path.join(os.path.dirname(__file__), "feature_stats.json")


def extract_training_vectors(pcap_path: str, max_packets: int = None):
    """
    Replay pcap_path through a FRESH set of the exact same
    feature-extraction components used live, and collect one
    feature vector per (source, completed 1-second window).

    max_packets:
        Optional cap on how many packets to read from the file.
        Useful for large public datasets (multi-GB pcaps) when
        you just want a fast first pass -- set to None to process
        the entire file.
    """

    flow_engine = FlowEngine(timeout=60)
    window_manager = WindowManager(window_seconds=1.0)
    source_aggregator = SourceAggregator()
    behavior_window = BehaviorWindow(window_seconds=10.0)
    beacon_tracker = BeaconTracker(window_seconds=300.0)
    dns_tracker = DNSTracker(window_seconds=30.0)
    tls_tracker = TLSTracker(window_seconds=300.0)

    vectors = []
    packet_count = 0

    def handle_completed_window(window_features, timestamp):
        security_features = calculate_security_features(window_features)
        source_features = source_aggregator.get_features(window_features["window_duration"])
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

        for source_ip in source_features.keys():
            combined = context.get_combined_source_features(source_ip)
            vectors.append(features_to_vector(combined))

        source_aggregator.reset()

    with PcapReader(pcap_path) as reader:
        for packet in reader:
            if max_packets is not None and packet_count >= max_packets:
                print(f"Reached --max-packets limit of {max_packets}, stopping early.")
                break

            if IP not in packet:
                continue

            ip = packet[IP]
            timestamp = float(packet.time)

            src_port = dst_port = protocol = tcp_flags = None
            tcp_syn = tcp_ack = tcp_rst = False

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
                            domain = raw_name.decode("utf-8", errors="ignore") \
                                if isinstance(raw_name, bytes) else str(raw_name)
                            dns_tracker.add_query(timestamp=timestamp, src_ip=ip.src, domain=domain)
                except Exception:
                    pass

            elif ICMP in packet:
                protocol = "ICMP"
            else:
                protocol = str(ip.proto)

            record = PacketRecord(
                timestamp=timestamp, src_ip=ip.src, dst_ip=ip.dst,
                src_port=src_port, dst_port=dst_port, protocol=str(protocol),
                packet_length=len(packet), tcp_flags=tcp_flags,
            )

            is_new_flow = flow_engine.is_new_flow(
                src_ip=ip.src, dst_ip=ip.dst,
                src_port=src_port or 0, dst_port=dst_port or 0, protocol=str(protocol),
            )
            flow_engine.process_packet(record)
            if is_new_flow:
                beacon_tracker.record_new_flow(timestamp=timestamp, src_ip=ip.src, dst_ip=ip.dst)

            window_features = window_manager.add_packet(
                timestamp=timestamp, src_ip=ip.src, dst_ip=ip.dst, protocol=protocol,
                packet_bytes=len(packet), src_port=src_port or 0, dst_port=dst_port or 0,
                tcp_syn=tcp_syn, tcp_ack=tcp_ack, tcp_rst=tcp_rst,
            )
            source_aggregator.add_packet(
                src_ip=ip.src, dst_ip=ip.dst, protocol=protocol, packet_bytes=len(packet),
                src_port=src_port or 0, dst_port=dst_port or 0,
                tcp_syn=tcp_syn, tcp_ack=tcp_ack, tcp_rst=tcp_rst,
            )
            behavior_window.add_packet(
                timestamp=timestamp, src_ip=ip.src, dst_ip=ip.dst, protocol=protocol,
                packet_bytes=len(packet), src_port=src_port or 0, dst_port=dst_port or 0,
                tcp_syn=tcp_syn, tcp_ack=tcp_ack, tcp_rst=tcp_rst,
            )

            packet_count += 1

            if window_features:
                handle_completed_window(window_features, timestamp)

    print(f"Processed {packet_count} packets from {pcap_path}")
    print(f"Collected {len(vectors)} per-source-window feature vectors")

    return np.array(vectors, dtype=float)


def train(pcap_path: str, contamination: float = 0.03, max_packets: int = None):
    print("=" * 60)
    print("CTD -- ML Model Training (REAL replayed traffic)")
    print("=" * 60)

    X = extract_training_vectors(pcap_path, max_packets=max_packets)

    if len(X) < 30:
        print(
            f"WARNING: only {len(X)} training samples collected. "
            "Isolation Forest needs a reasonably sized, varied benign "
            "traffic sample -- consider a longer/busier capture."
        )

    print(f"Training data shape: {X.shape}")

    model = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
    model.fit(X)
    print("Training complete.")

    means = X.mean(axis=0)
    stds = np.where(X.std(axis=0) < 1e-6, 1e-6, X.std(axis=0))

    stats = {name: {"mean": float(m), "std": float(s)} for name, m, s in zip(FEATURE_NAMES, means, stds)}

    with open(STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"Saved feature statistics -> {STATS_PATH}")

    joblib.dump(model, MODEL_PATH)
    print(f"Saved trained model -> {MODEL_PATH}")

    predictions = model.predict(X)
    n_flagged = int((predictions == -1).sum())
    print(
        f"{n_flagged} / {len(X)} training points flagged as anomalies "
        f"({n_flagged / max(len(X), 1):.1%}) -- should roughly match "
        f"the contamination setting ({contamination:.1%})."
    )


def main():
    parser = argparse.ArgumentParser(description="Train the ML model on real replayed benign traffic")
    parser.add_argument("pcap_path", help="Path to a benign-only .pcap/.pcapng file")
    parser.add_argument(
        "--contamination", type=float, default=0.03,
        help="Expected fraction of the benign set that's still borderline/noisy (default: 0.03)"
    )
    parser.add_argument(
        "--max-packets", type=int, default=None,
        help="Optional cap on packets read (useful for large multi-GB public datasets)"
    )
    args = parser.parse_args()
    train(args.pcap_path, contamination=args.contamination, max_packets=args.max_packets)


if __name__ == "__main__":
    main()
