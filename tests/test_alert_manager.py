from alerts.alert_manager import AlertManager
from detectors.detection_result import DetectionResult


def make_port_scan():

    return DetectionResult(
        detected=True,
        attack_type="PORT_SCAN",
        severity="HIGH",
        score=4,
        confidence=1.0,
        reasons=[
            "high destination-port diversity",
            "multiple connection attempts",
        ],
    )


def make_syn_flood():

    return DetectionResult(
        detected=True,
        attack_type="SYN_FLOOD",
        severity="HIGH",
        score=3,
        confidence=1.0,
        reasons=[
            "high SYN packet ratio",
            "high SYN rate",
        ],
    )


def main():

    print("=" * 70)
    print("CTD — ALERT MANAGER TEST")
    print("=" * 70)

    manager = AlertManager(
        resolve_after=10.0
    )

    # --------------------------------------------------
    # 1. First attack
    # --------------------------------------------------

    alerts = manager.process(
        source_ip="10.10.10.10",
        detections=[make_port_scan()],
        timestamp=100.0,
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.status == "ACTIVE"
    assert alert.event_count == 1

    print("\n1. New attack")
    print("-" * 70)
    print(alert.to_dict())

    # --------------------------------------------------
    # 2. Same attack continues
    # --------------------------------------------------

    alerts = manager.process(
        source_ip="10.10.10.10",
        detections=[make_port_scan()],
        timestamp=105.0,
    )

    assert len(alerts) == 1

    assert alerts[0].alert_id == alert.alert_id
    assert alerts[0].event_count == 2
    assert alerts[0].status == "ACTIVE"

    print("\n2. Same attack continues")
    print("-" * 70)
    print(alerts[0].to_dict())

    # --------------------------------------------------
    # 3. Different attack
    # --------------------------------------------------

    alerts = manager.process(
        source_ip="10.10.10.20",
        detections=[make_syn_flood()],
        timestamp=106.0,
    )

    assert len(alerts) == 1

    assert alerts[0].attack_type == "SYN_FLOOD"

    print("\n3. Different source / attack")
    print("-" * 70)
    print(alerts[0].to_dict())

    # --------------------------------------------------
    # 4. Resolve stale alerts
    # --------------------------------------------------

    resolved = manager.resolve_stale(
        timestamp=116.0
    )

    assert len(resolved) == 2

    assert all(
        alert.status == "RESOLVED"
        for alert in resolved
    )

    print("\n4. Attacks stopped")
    print("-" * 70)

    for alert in resolved:
        print(alert.to_dict())

    # --------------------------------------------------
    # 5. History must remain
    # --------------------------------------------------

    history = manager.history()

    assert len(history) == 2

    print("\n5. Historical attacks")
    print("-" * 70)

    for alert in history:
        print(alert.to_dict())

    # --------------------------------------------------
    # 6. Same attacker attacks again
    # --------------------------------------------------

    alerts = manager.process(
        source_ip="10.10.10.10",
        detections=[make_port_scan()],
        timestamp=130.0,
    )

    assert len(alerts) == 1

    assert alerts[0].alert_id != alert.alert_id
    assert alerts[0].event_count == 1
    assert alerts[0].status == "ACTIVE"

    print("\n6. Same attacker attacks again")
    print("-" * 70)
    print(alerts[0].to_dict())

    # --------------------------------------------------
    # Final state
    # --------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL STATE")
    print("=" * 70)

    print(
        f"Active alerts   : "
        f"{len(manager.active_alerts())}"
    )

    print(
        f"History records : "
        f"{len(manager.history())}"
    )

    print("\nTEST PASSED")


if __name__ == "__main__":
    main()
