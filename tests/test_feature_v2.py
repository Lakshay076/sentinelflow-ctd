from features.window import WindowManager


def main():

    manager = WindowManager(window_seconds=1.0)

    print("=" * 60)
    print("CTD — Bidirectional Feature Test")
    print("=" * 60)

    packets = [
        # Kali -> Ubuntu
        {
            "timestamp": 0.10,
            "src_ip": "10.10.10.10",
            "dst_ip": "10.10.10.20",
            "protocol": "TCP",
            "packet_bytes": 100,
            "src_port": 50000,
            "dst_port": 9000,
        },

        # Kali -> Ubuntu
        {
            "timestamp": 0.20,
            "src_ip": "10.10.10.10",
            "dst_ip": "10.10.10.20",
            "protocol": "TCP",
            "packet_bytes": 150,
            "src_port": 50000,
            "dst_port": 9000,
        },

        # Ubuntu -> Kali
        {
            "timestamp": 0.40,
            "src_ip": "10.10.10.20",
            "dst_ip": "10.10.10.10",
            "protocol": "TCP",
            "packet_bytes": 200,
            "src_port": 9000,
            "dst_port": 50000,
        },

        # Ubuntu -> Kali
        {
            "timestamp": 0.60,
            "src_ip": "10.10.10.20",
            "dst_ip": "10.10.10.10",
            "protocol": "TCP",
            "packet_bytes": 250,
            "src_port": 9000,
            "dst_port": 50000,
        },

        # This packet forces the first window to complete
        {
            "timestamp": 1.10,
            "src_ip": "10.10.10.10",
            "dst_ip": "10.10.10.20",
            "protocol": "TCP",
            "packet_bytes": 100,
            "src_port": 50000,
            "dst_port": 9000,
        },
    ]

    result = None

    for packet in packets:

        result = manager.add_packet(**packet)

    if result:

        print()
        print("WINDOW COMPLETED")
        print("-" * 40)

        for key, value in result.items():
            print(f"{key}: {value}")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
