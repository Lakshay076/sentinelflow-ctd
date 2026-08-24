from features.security_features import calculate_security_features


def print_features(title, features):

    print()
    print("=" * 60)
    print(title)
    print("=" * 60)

    for key, value in features.items():
        print(f"{key:30} : {value:.4f}")


def main():

    # --------------------------------------------------
    # NORMAL TRAFFIC
    # --------------------------------------------------

    normal = {
        "window_duration": 1.0,
        "packets": 20,
        "tcp_syn": 2,
        "tcp_ack": 10,
        "tcp_rst": 0,
        "active_flows": 2,
        "unique_destination_ports": 1,
        "unique_sources": 1,
        "unique_destinations": 1,
    }

    normal_features = calculate_security_features(normal)

    print_features(
        "NORMAL TRAFFIC",
        normal_features
    )

    # --------------------------------------------------
    # PORT SCAN-LIKE TRAFFIC
    # --------------------------------------------------

    port_scan = {
        "window_duration": 1.0,
        "packets": 30,
        "tcp_syn": 25,
        "tcp_ack": 2,
        "tcp_rst": 3,
        "active_flows": 25,
        "unique_destination_ports": 20,
        "unique_sources": 1,
        "unique_destinations": 1,
    }

    port_scan_features = calculate_security_features(
        port_scan
    )

    print_features(
        "PORT SCAN-LIKE TRAFFIC",
        port_scan_features
    )

    # --------------------------------------------------
    # SYN FLOOD-LIKE TRAFFIC
    # --------------------------------------------------

    syn_flood = {
        "window_duration": 1.0,
        "packets": 1000,
        "tcp_syn": 950,
        "tcp_ack": 20,
        "tcp_rst": 5,
        "active_flows": 950,
        "unique_destination_ports": 1,
        "unique_sources": 1,
        "unique_destinations": 1,
    }

    syn_flood_features = calculate_security_features(
        syn_flood
    )

    print_features(
        "SYN FLOOD-LIKE TRAFFIC",
        syn_flood_features
    )


if __name__ == "__main__":
    main()
