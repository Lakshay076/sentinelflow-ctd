from detectors.scan_detector import detect_port_scan


def print_result(title, features):

    print()
    print("=" * 70)
    print(title)
    print("=" * 70)

    result = detect_port_scan(features)

    for key, value in result.items():

        print(f"{key:15} : {value}")


def main():

    # --------------------------------------------------
    # Normal traffic
    # --------------------------------------------------

    normal = {

        "unique_destination_ports": 1,

        "active_flows": 1,

        "syn_packet_ratio": 0.20,

        "flows_per_second": 1.0,
    }

    print_result(
        "NORMAL TRAFFIC",
        normal
    )

    # --------------------------------------------------
    # Port scan
    # --------------------------------------------------

    port_scan = {

        "unique_destination_ports": 10,

        "active_flows": 11,

        "syn_packet_ratio": 0.846,

        "flows_per_second": 11.0,
    }

    print_result(
        "PORT SCAN",
        port_scan
    )


if __name__ == "__main__":
    main()
