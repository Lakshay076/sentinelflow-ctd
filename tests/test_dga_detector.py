import random
import string

from features.dns_tracker import DNSTracker
from detectors.dga_detector import detect_dga_dns


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
    # Normal browsing DNS lookups
    # --------------------------------------------------

    tracker = DNSTracker(window_seconds=30)

    t = 1000.0
    normal_domains = [
        "google.com", "youtube.com", "github.com",
        "wikipedia.org", "amazon.in", "google.com",
    ]

    for domain in normal_domains:
        tracker.add_query(t, "10.0.0.5", domain)
        t += 3

    features = tracker.get_features(t)

    print_result(
        "NORMAL DNS TRAFFIC",
        detect_dga_dns(features.get("10.0.0.5", {})),
    )

    # --------------------------------------------------
    # DGA-style: many random-looking domain names,
    # queried quickly.
    # --------------------------------------------------

    tracker2 = DNSTracker(window_seconds=30)

    t = 1000.0
    for i in range(10):
        fake_name = "".join(
            random.choices(
                string.ascii_lowercase + string.digits,
                k=16,
            )
        )
        domain = f"{fake_name}.evil-c2.net"
        tracker2.add_query(t, "10.0.0.9", domain)
        t += 1.5

    features2 = tracker2.get_features(t)

    print_result(
        "DGA / DNS TUNNELLING",
        detect_dga_dns(features2.get("10.0.0.9", {})),
    )


if __name__ == "__main__":
    main()
