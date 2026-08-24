from features.window import WindowManager


def main():

    manager = WindowManager(window_seconds=1.0)

    print("=" * 60)
    print("CTD — Fixed Observation Window Test")
    print("=" * 60)

    base_time = 1000.0

    packets = [
        (1000.10, 100),
        (1000.20, 100),
        (1000.70, 100),
        (1001.10, 100),
        (1001.80, 100),
        (1002.20, 100),
    ]

    completed = []

    for timestamp, packet_size in packets:

        result = manager.add_packet(
            timestamp=timestamp,
            src_ip="10.10.10.10",
            dst_ip="10.10.10.20",
            protocol="TCP",
            packet_bytes=packet_size,
            src_port=50000,
            dst_port=9000,
            tcp_syn=False,
            tcp_ack=True,
        )

        print(
            f"Packet at t={timestamp - base_time:.2f}s"
        )

        if result:

            completed.append(result)

            print("\nWINDOW COMPLETED")
            print("-" * 40)

            for key, value in result.items():
                print(f"{key}: {value}")

            print()

    print("=" * 60)
    print(f"Completed windows: {len(completed)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
