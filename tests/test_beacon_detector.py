from features.beacon_tracker import BeaconTracker
from detectors.beacon_detector import detect_c2_beaconing


def print_result(label, result):

    print()
    print("=" * 70)
    print(label)
    print("=" * 70)

    print("Detected    :", result.detected)
    print("Attack type :", result.attack_type)
    print("Severity    :", result.severity)
    print("Confidence  :", result.confidence)

    print("Reasons:")
    for reason in result.reasons:
        print("  -", reason)


def main():

    # --------------------------------------------------
    # Simulated C2 beacon: connects to the same server
    # every ~60 seconds, very regularly.
    # --------------------------------------------------

    tracker = BeaconTracker(window_seconds=300)

    t = 1000.0
    for i in range(6):
        tracker.record_new_flow(t, "10.0.0.9", "203.0.113.9")
        t += 60.2  # tiny jitter, still very regular

    features = tracker.get_features(t)

    print_result(
        "BOTNET C2 BEACONING",
        detect_c2_beaconing(features.get("10.0.0.9", {})),
    )

    # --------------------------------------------------
    # Normal human browsing: irregular gaps, several
    # different sites.
    # --------------------------------------------------

    tracker2 = BeaconTracker(window_seconds=300)

    t = 1000.0
    sites = [
        "1.1.1.1", "2.2.2.2", "3.3.3.3",
        "4.4.4.4", "5.5.5.5",
    ]

    import random
    for i in range(8):
        tracker2.record_new_flow(
            t, "10.0.0.20", random.choice(sites)
        )
        t += random.uniform(5, 90)

    features2 = tracker2.get_features(t)

    print_result(
        "NORMAL BROWSING",
        detect_c2_beaconing(features2.get("10.0.0.20", {})),
    )


if __name__ == "__main__":
    main()
