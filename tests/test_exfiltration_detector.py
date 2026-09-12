from detectors.exfiltration_detector import detect_exfiltration


def show(name, features, expected):
    result = detect_exfiltration(features)

    print()
    print("=" * 70)
    print(name)
    print("=" * 70)
    print(f"Detected   : {result.detected}")
    print(f"Type       : {result.attack_type}")
    print(f"Severity   : {result.severity}")
    print(f"Score      : {result.score}")
    print(f"Confidence : {result.confidence:.2f}")

    for reason in result.reasons:
        print(f" - {reason}")

    assert result.detected == expected


def main():

    # --------------------------------------------------
    # Case 1: 229 KB in a single observation window.
    # Below the 500 KB exfiltration volume threshold.
    # --------------------------------------------------

    small_burst = {
        "packets": 20,
        "bytes": 229_504,
        "bytes_received": 1_130,
        "outbound_inbound_ratio": 203.1,
        "bytes_per_second": 229_504,
    }

    show(
        "SMALL ONE-SECOND BURST",
        small_burst,
        expected=False,
    )

    # --------------------------------------------------
    # Case 2: 600 KB accumulated across the
    # 10-second rolling behavioral window.
    # --------------------------------------------------

    rolling_exfiltration = {
        "exfil_bytes_sent": 600_000,
        "exfil_bytes_received": 5_000,
        "exfil_outbound_inbound_ratio": 120.0,
        "exfil_packets": 600,
        "exfil_bytes_per_second": 60_000,
    }

    show(
        "ROLLING 10-SECOND EXFILTRATION",
        rolling_exfiltration,
        expected=True,
    )

    print()
    print("=" * 70)
    print("EXFILTRATION DETECTOR TEST PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()
