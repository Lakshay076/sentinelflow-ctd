from features.behavior_window import BehaviorWindow


def print_sources(features):

    for source_ip, source in features.items():

        print()
        print(f"SOURCE: {source_ip}")
        print("-" * 60)

        for key, value in source.items():

            if isinstance(value, float):
                print(
                    f"{key:30} : {value:.3f}"
                )
            else:
                print(
                    f"{key:30} : {value}"
                )


def main():

    window = BehaviorWindow(
        window_seconds=10.0
    )

    print("=" * 70)
    print("CTD — ROLLING BEHAVIOR WINDOW TEST")
    print("=" * 70)

    # --------------------------------------------------
    # Simulate packets from a scanner
    # --------------------------------------------------

    packets = [

        (1.0, 22),
        (2.0, 23),
        (3.0, 25),
        (4.0, 53),
        (5.0, 80),
        (6.0, 110),
        (7.0, 139),
        (8.0, 443),
        (9.0, 445),
        (10.0, 8080),
    ]

    for timestamp, port in packets:

        window.add_packet(
            timestamp=timestamp,
            src_ip="10.10.10.10",
            dst_ip="10.10.10.20",
            protocol="TCP",
            packet_bytes=74,
            src_port=40000 + port,
            dst_port=port,
            tcp_syn=True,
        )

        print(
            f"Packet at t={timestamp:.1f}s "
            f"-> destination port {port}"
        )

    print()
    print("=" * 70)
    print("BEHAVIOR AT t=10s")
    print("=" * 70)

    features = window.get_source_features(
        current_timestamp=10.0
    )

    print_sources(features)

    # --------------------------------------------------
    # Move forward in time
    #
    # Packets older than 10 seconds should expire.
    # --------------------------------------------------

    window.add_packet(
        timestamp=21.0,
        src_ip="10.10.10.30",
        dst_ip="10.10.10.20",
        protocol="TCP",
        packet_bytes=74,
        src_port=50000,
        dst_port=80,
        tcp_syn=True,
    )

    print()
    print("=" * 70)
    print("BEHAVIOR AT t=21s")
    print("=" * 70)

    features = window.get_source_features(
        current_timestamp=21.0
    )

    print_sources(features)

    print()
    print(
        "Events currently stored:",
        window.size()
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
