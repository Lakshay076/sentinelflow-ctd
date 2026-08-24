
from features.feature_context import FeatureContext
from detectors.detector_engine import DetectorEngine


def main():

    network_features = {
        "packets": 1000,
        "bytes": 80000,
        "tcp_syn": 100,
        "active_flows": 50,
    }

    source_features = {

        # Simulated port scanner
        "10.10.10.10": {
            "packets": 20,
            "bytes": 1480,
            "tcp_packets": 20,
            "udp_packets": 0,
            "icmp_packets": 0,
            "tcp_syn": 17,
            "tcp_ack": 2,
            "tcp_rst": 1,
            "unique_destinations": 1,
            "unique_destination_ports": 10,
            "active_flows": 11,
            "flows_per_second": 11.0,
            "syn_packet_ratio": 0.85,
            "rst_packet_ratio": 0.05,
            "ports_per_destination": 10.0,
        },

        # Normal source
        "10.10.10.30": {
            "packets": 20,
            "bytes": 1600,
            "tcp_packets": 20,
            "udp_packets": 0,
            "icmp_packets": 0,
            "tcp_syn": 2,
            "tcp_ack": 18,
            "tcp_rst": 0,
            "unique_destinations": 1,
            "unique_destination_ports": 1,
            "active_flows": 1,
            "flows_per_second": 1.0,
            "syn_packet_ratio": 0.10,
            "rst_packet_ratio": 0.0,
            "ports_per_destination": 1.0,
        },
    }

    behavior_features = {
        "10.10.10.10": {
            "packets": 80,
            "bytes": 6000,
            "tcp_packets": 80,
            "udp_packets": 0,
            "icmp_packets": 0,
            "tcp_syn": 68,
            "tcp_ack": 5,
            "tcp_rst": 2,
            "unique_destinations": 1,
            "unique_destination_ports": 10,
            "active_flows": 11,
            "flows_per_second": 11.0,
            "syn_packet_ratio": 0.85,
            "rst_packet_ratio": 0.025,
            "ports_per_destination": 10.0,
        },

        "10.10.10.30": {
            "packets": 20,
            "bytes": 1500,
            "tcp_packets": 20,
            "udp_packets": 0,
            "icmp_packets": 0,
            "tcp_syn": 1,
            "tcp_ack": 18,
            "tcp_rst": 0,
            "unique_destinations": 1,
            "unique_destination_ports": 1,
            "active_flows": 1,
            "flows_per_second": 1.0,
            "syn_packet_ratio": 0.05,
            "rst_packet_ratio": 0.0,
            "ports_per_destination": 1.0,
        },
    }

    context = FeatureContext(
        network=network_features,
        security={},
        sources=source_features,
        behavior=behavior_features,
    )

    engine = DetectorEngine()

    detections = engine.analyze_context(context)

    print("=" * 70)
    print("CTD — CONTEXT DETECTOR TEST")
    print("=" * 70)

    for source_ip, results in detections.items():

        print()
        print(f"Source: {source_ip}")
        print("-" * 70)

        if not results:

            print("No detections")

            continue

        for result in results:

            print(f"Attack type : {result.attack_type}")
            print(f"Severity    : {result.severity}")
            print(f"Score       : {result.score}")
            print(f"Confidence  : {result.confidence}")

            print("Reasons:")

            for reason in result.reasons:
                print(f"  - {reason}")

    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
