from detectors.detector_engine import DetectorEngine


def main():

    engine = DetectorEngine()

    # --------------------------------------------------
    # Normal traffic
    # --------------------------------------------------

    normal = {

        "unique_destination_ports": 1,

        "active_flows": 1,

        "syn_packet_ratio": 0.20,

        "flows_per_second": 1.0,
    }

    print()
    print("=" * 70)
    print("NORMAL TRAFFIC")
    print("=" * 70)

    results = engine.analyze(normal)

    print("Detections:", len(results))

    # --------------------------------------------------
    # Port scan
    # --------------------------------------------------

    scan = {

        "unique_destination_ports": 10,

        "active_flows": 11,

        "syn_packet_ratio": 0.846,

        "flows_per_second": 11.0,
    }

    print()
    print("=" * 70)
    print("PORT SCAN")
    print("=" * 70)

    results = engine.analyze(scan)

    print("Detections:", len(results))

    for result in results:

        print()
        print("Attack type :", result.attack_type)
        print("Severity    :", result.severity)
        print("Score       :", result.score)
        print("Confidence  :", result.confidence)

        print("Reasons:")

        for reason in result.reasons:

            print("  -", reason)
    # --------------------------------------------------
    # SYN flood
    # --------------------------------------------------

    syn_flood = {

        "unique_destination_ports": 1,

        "active_flows": 950,

        "syn_packet_ratio": 0.95,

        "syn_rate": 950.0,

        "flows_per_second": 950.0,
    }

    print()
    print("=" * 70)
    print("SYN FLOOD")
    print("=" * 70)

    results = engine.analyze(syn_flood)

    print("Detections:", len(results))

    for result in results:

        print()
        print("Attack type :", result.attack_type)
        print("Severity    :", result.severity)
        print("Score       :", result.score)
        print("Confidence  :", result.confidence)

        print("Reasons:")

        for reason in result.reasons:

            print("  -", reason)

if __name__ == "__main__":
    main()

