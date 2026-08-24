from features.feature_context import FeatureContext


def main():

    network_features = {
        "packets": 100,
        "bytes": 8000,
        "tcp_syn": 20,
        "active_flows": 15,
    }

    source_features = {
        "10.10.10.10": {
            "packets": 80,
            "unique_destination_ports": 10,
            "active_flows": 11,
            "syn_packet_ratio": 0.85,
            "flows_per_second": 11.0,
        },
        "10.10.10.30": {
            "packets": 20,
            "unique_destination_ports": 1,
            "active_flows": 1,
            "syn_packet_ratio": 0.05,
            "flows_per_second": 1.0,
        },
    }

    context = FeatureContext(
        network=network_features,
        sources=source_features,
    )

    print("=" * 70)
    print("CTD — FEATURE CONTEXT TEST")
    print("=" * 70)

    print("\nNetwork features")
    print("-" * 70)

    for key, value in context.network.items():
        print(f"{key:30} : {value}")

    print("\nSources")
    print("-" * 70)

    for source_ip in context.source_ips():

        print(f"\nSource: {source_ip}")

        features = context.get_source_features(source_ip)

        for key, value in features.items():
            print(f"{key:30} : {value}")

    print("\nContext lookup test")
    print("-" * 70)

    source = context.get_source_features("10.10.10.10")

    print(
        "10.10.10.10 destination ports:",
        source["unique_destination_ports"]
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
