from features.behavior_window import BehaviorWindow
from features.feature_context import FeatureContext
from detectors.detector_engine import DetectorEngine


def main():

    print("=" * 70)
    print("CTD — ROLLING STREAM DETECTOR TEST")
    print("=" * 70)

    behavior_window = BehaviorWindow(
        window_seconds=10.0
    )

    engine = DetectorEngine()

    source_ip = "10.10.10.10"
    destination_ip = "10.10.10.20"

    ports = [
        22,
        23,
        25,
        53,
        80,
        110,
        139,
        443,
        445,
        8080,
    ]

    print("\nSimulating port-scan stream...")
    print("-" * 70)

    for i, port in enumerate(ports, start=1):

        timestamp = float(i)

        behavior_window.add_packet(
            timestamp=timestamp,
            src_ip=source_ip,
            dst_ip=destination_ip,
            protocol="TCP",
            packet_bytes=74,
            src_port=50000 + i,
            dst_port=port,
            tcp_syn=True,
            tcp_ack=False,
            tcp_rst=False,
        )

        print(
            f"t={timestamp:4.1f}s  "
            f"{source_ip} -> "
            f"{destination_ip}:{port}"
        )

    behavior_features = (
        behavior_window.get_source_features(
            current_timestamp=10.0
        )
    )

    context = FeatureContext(
        network={},
        security={},
        sources={},
        behavior=behavior_features,
    )

    detections = engine.analyze_context(
        context
    )

    print("\n" + "=" * 70)
    print("ROLLING BEHAVIOR")
    print("=" * 70)

    for source_ip, features in behavior_features.items():

        print(f"\nSource: {source_ip}")

        print(
            f"destination ports : "
            f"{features['unique_destination_ports']}"
        )

        print(
            f"active flows      : "
            f"{features['active_flows']}"
        )

        print(
            f"SYN ratio         : "
            f"{features['syn_packet_ratio']:.2f}"
        )

        print(
            f"flows/sec         : "
            f"{features['flows_per_second']:.2f}"
        )

    print("\n" + "=" * 70)
    print("DETECTIONS")
    print("=" * 70)

    total = 0

    for source_ip, results in detections.items():

        for result in results:

            total += 1

            print(
                f"\nSource      : {source_ip}"
            )

            print(
                f"Attack type : {result.attack_type}"
            )

            print(
                f"Severity    : {result.severity}"
            )

            print(
                f"Score       : {result.score}"
            )

            print(
                f"Confidence  : {result.confidence}"
            )

            for reason in result.reasons:

                print(
                    f"  - {reason}"
                )

    if total == 0:

        print("\nNO DETECTIONS")

    print("\n" + "=" * 70)

    assert total >= 1, (
        "Expected PORT_SCAN detection"
    )

    assert any(
        result.attack_type == "PORT_SCAN"
        for results in detections.values()
        for result in results
    ), (
        "Expected PORT_SCAN detection"
    )

    print(
        "TEST PASSED — rolling behavior "
        "reached the detector."
    )


if __name__ == "__main__":
    main()
