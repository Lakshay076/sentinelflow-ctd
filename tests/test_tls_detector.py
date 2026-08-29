from features.tls_parser import parse_client_hello, compute_ja3
from features.tls_tracker import TLSTracker
from detectors.tls_detector import detect_tls_anomaly


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
    # A browser-like TLS client: many cipher suites,
    # many extensions, SNI present, talking to several
    # different sites.
    # --------------------------------------------------

    tracker = TLSTracker(window_seconds=300)

    t = 1000.0
    for i in range(5):
        tracker.add_client_hello(
            timestamp=t,
            src_ip="10.0.0.5",
            dst_ip=f"93.0.0.{i}",
            ja3_hash="realistic-browser-ja3",
            cipher_count=30,
            extension_count=11,
            has_sni=True,
        )
        t += 2

    features = tracker.get_features(t)

    print_result(
        "BROWSER-LIKE TLS TRAFFIC",
        detect_tls_anomaly(features.get("10.0.0.5", {})),
    )

    # --------------------------------------------------
    # A minimal, malware-like TLS client: very few
    # ciphers/extensions, no SNI, same fingerprint
    # repeated to the same server (looks like a script,
    # not a browser).
    # --------------------------------------------------

    tracker2 = TLSTracker(window_seconds=300)

    t = 1000.0
    for i in range(6):
        tracker2.add_client_hello(
            timestamp=t,
            src_ip="10.0.0.9",
            dst_ip="203.0.113.9",
            ja3_hash="minimal-client-ja3",
            cipher_count=3,
            extension_count=2,
            has_sni=False,
        )
        t += 60

    features2 = tracker2.get_features(t)

    print_result(
        "MINIMAL / MALWARE-LIKE TLS TRAFFIC",
        detect_tls_anomaly(features2.get("10.0.0.9", {})),
    )


if __name__ == "__main__":
    main()
