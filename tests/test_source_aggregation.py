from features.source_aggregation import SourceAggregator


def main():

    aggregator = SourceAggregator()

    # --------------------------------------------------
    # Normal client traffic
    # --------------------------------------------------

    aggregator.add_packet(
        src_ip="10.10.10.10",
        dst_ip="10.10.10.20",
        protocol="TCP",
        packet_bytes=74,
        src_port=50000,
        dst_port=80,
        tcp_syn=True,
    )

    aggregator.add_packet(
        src_ip="10.10.10.10",
        dst_ip="10.10.10.20",
        protocol="TCP",
        packet_bytes=66,
        src_port=50000,
        dst_port=80,
        tcp_ack=True,
    )

    # --------------------------------------------------
    # Another source
    # --------------------------------------------------

    aggregator.add_packet(
        src_ip="10.10.10.30",
        dst_ip="10.10.10.20",
        protocol="TCP",
        packet_bytes=74,
        src_port=40000,
        dst_port=443,
        tcp_syn=True,
    )

    # --------------------------------------------------
    # Print
    # --------------------------------------------------

    features = aggregator.get_features(1.0)

    print("=" * 70)
    print("CTD — PER SOURCE AGGREGATION TEST")
    print("=" * 70)

    for source_ip, values in features.items():

        print()
        print(f"SOURCE: {source_ip}")
        print("-" * 70)

        for key, value in values.items():

            if isinstance(value, float):
                print(f"{key:30} : {value:.3f}")
            else:
                print(f"{key:30} : {value}")

    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
