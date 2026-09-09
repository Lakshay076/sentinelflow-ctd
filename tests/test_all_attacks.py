"""
CTD — Comprehensive Attack Detection Test Suite

Tests all detectors against simulated normal and attack feature profiles:
1. Port Scan
2. SYN Flood
3. Data Exfiltration
4. Botnet C2 Beaconing
5. DGA / DNS Tunnelling
6. TLS Metadata Anomaly
7. Detector Engine Context Analysis
"""

from detectors.scan_detector import detect_port_scan
from detectors.syn_flood_detector import detect_syn_flood
from detectors.exfiltration_detector import detect_exfiltration
from detectors.beacon_detector import detect_c2_beaconing
from detectors.dga_detector import detect_dga_dns
from detectors.tls_detector import detect_tls_anomaly
from detectors.detector_engine import DetectorEngine
from features.feature_context import FeatureContext


def test_port_scan():
    print("\n[1] Testing PORT SCAN Detector...")
    normal = {
        "unique_destination_ports": 1,
        "active_flows": 1,
        "syn_packet_ratio": 0.1,
        "flows_per_second": 1.0,
    }
    attack = {
        "unique_destination_ports": 12,
        "active_flows": 12,
        "syn_packet_ratio": 0.9,
        "flows_per_second": 12.0,
    }
    res_normal = detect_port_scan(normal)
    res_attack = detect_port_scan(attack)

    assert not res_normal.detected, "Normal traffic incorrectly flagged as port scan"
    assert res_attack.detected and res_attack.attack_type == "PORT_SCAN", "Port scan failed to detect"
    print(f"  ✓ Normal: detected={res_normal.detected}")
    print(f"  ✓ Attack: detected={res_attack.detected}, severity={res_attack.severity}, confidence={res_attack.confidence}")


def test_syn_flood():
    print("\n[2] Testing SYN FLOOD Detector...")
    normal = {
        "syn_packet_ratio": 0.15,
        "syn_rate": 2.0,
        "flows_per_second": 2.0,
    }
    attack = {
        "syn_packet_ratio": 0.95,
        "syn_rate": 150.0,
        "flows_per_second": 150.0,
    }
    res_normal = detect_syn_flood(normal)
    res_attack = detect_syn_flood(attack)

    assert not res_normal.detected, "Normal traffic incorrectly flagged as SYN flood"
    assert res_attack.detected and res_attack.attack_type == "SYN_FLOOD", "SYN flood failed to detect"
    print(f"  ✓ Normal: detected={res_normal.detected}")
    print(f"  ✓ Attack: detected={res_attack.detected}, severity={res_attack.severity}, confidence={res_attack.confidence}")


def test_exfiltration():
    print("\n[3] Testing DATA EXFILTRATION Detector...")
    normal = {
        "bytes": 50_000,
        "bytes_received": 200_000,
        "outbound_inbound_ratio": 0.25,
        "packets": 50,
        "bytes_per_second": 5_000.0,
    }
    attack = {
        "bytes": 800_000,
        "bytes_received": 10_000,
        "outbound_inbound_ratio": 80.0,
        "packets": 500,
        "bytes_per_second": 80_000.0,
    }
    res_normal = detect_exfiltration(normal)
    res_attack = detect_exfiltration(attack)

    assert not res_normal.detected, "Normal traffic incorrectly flagged as exfiltration"
    assert res_attack.detected and res_attack.attack_type == "DATA_EXFILTRATION", "Exfiltration failed to detect"
    print(f"  ✓ Normal: detected={res_normal.detected}")
    print(f"  ✓ Attack: detected={res_attack.detected}, severity={res_attack.severity}, confidence={res_attack.confidence}")


def test_c2_beaconing():
    print("\n[4] Testing C2 BEACONING Detector...")
    normal = {
        "beacon_connection_count": 2,
        "beacon_interval_cv": 0.85,
        "beacon_mean_interval": 25.0,
        "beacon_repeated_destinations": 5,
    }
    attack = {
        "beacon_connection_count": 8,
        "beacon_interval_cv": 0.05,
        "beacon_mean_interval": 30.0,
        "beacon_repeated_destinations": 1,
    }
    res_normal = detect_c2_beaconing(normal)
    res_attack = detect_c2_beaconing(attack)

    assert not res_normal.detected, "Normal browsing incorrectly flagged as C2 beaconing"
    assert res_attack.detected and res_attack.attack_type == "C2_BEACONING", "C2 beaconing failed to detect"
    print(f"  ✓ Normal: detected={res_normal.detected}")
    print(f"  ✓ Attack: detected={res_attack.detected}, severity={res_attack.severity}, confidence={res_attack.confidence}")


def test_dga_dns():
    print("\n[5] Testing DGA / DNS TUNNELLING Detector...")
    normal = {
        "dns_query_count": 6,
        "dns_high_entropy_ratio": 0.0,
        "dns_unique_domains": 4,
        "dns_mean_length": 14.0,
        "dns_queries_per_second": 0.5,
    }
    attack = {
        "dns_query_count": 15,
        "dns_high_entropy_ratio": 0.9,
        "dns_unique_domains": 12,
        "dns_mean_length": 45.0,
        "dns_queries_per_second": 3.5,
    }
    res_normal = detect_dga_dns(normal)
    res_attack = detect_dga_dns(attack)

    assert not res_normal.detected, "Normal DNS queries incorrectly flagged as DGA"
    assert res_attack.detected and res_attack.attack_type == "DGA_DNS_TUNNELLING", "DGA failed to detect"
    print(f"  ✓ Normal: detected={res_normal.detected}")
    print(f"  ✓ Attack: detected={res_attack.detected}, severity={res_attack.severity}, confidence={res_attack.confidence}")


def test_tls_anomaly():
    print("\n[6] Testing TLS METADATA ANOMALY Detector...")
    normal = {
        "tls_client_hello_count": 5,
        "tls_avg_cipher_count": 28,
        "tls_avg_extension_count": 12,
        "tls_missing_sni_ratio": 0.0,
        "tls_max_same_ja3_to_one_dest": 1,
    }
    attack = {
        "tls_client_hello_count": 8,
        "tls_avg_cipher_count": 2,
        "tls_avg_extension_count": 1,
        "tls_missing_sni_ratio": 1.0,
        "tls_max_same_ja3_to_one_dest": 8,
    }
    res_normal = detect_tls_anomaly(normal)
    res_attack = detect_tls_anomaly(attack)

    assert not res_normal.detected, "Standard TLS client incorrectly flagged as anomalous"
    assert res_attack.detected and res_attack.attack_type == "TLS_METADATA_ANOMALY", "TLS anomaly failed to detect"
    print(f"  ✓ Normal: detected={res_normal.detected}")
    print(f"  ✓ Attack: detected={res_attack.detected}, severity={res_attack.severity}, confidence={res_attack.confidence}")


def test_detector_engine_e2e():
    print("\n[7] Testing DetectorEngine End-to-End Analysis...")
    engine = DetectorEngine(use_ml=False)

    source_features = {
        "192.168.1.100": {
            "unique_destination_ports": 20,
            "active_flows": 20,
            "syn_packet_ratio": 0.9,
            "flows_per_second": 20.0,
        },
        "192.168.1.101": {
            "unique_destination_ports": 1,
            "active_flows": 1,
            "syn_packet_ratio": 0.05,
            "flows_per_second": 1.0,
        }
    }

    context = FeatureContext(
        network={"packets": 500, "bytes": 40000},
        sources=source_features,
    )

    detections = engine.analyze_context(context)

    assert "192.168.1.100" in detections and len(detections["192.168.1.100"]) >= 1, "Attacker IP not detected in context"
    assert "192.168.1.101" in detections and len(detections["192.168.1.101"]) == 0, "Benign IP falsely flagged in context"

    print(f"  ✓ Attacker 192.168.1.100 detections: {[r.attack_type for r in detections['192.168.1.100']]}")
    print(f"  ✓ Benign 192.168.1.101 detections: {len(detections['192.168.1.101'])}")


def main():
    print("=" * 70)
    print("SENTINELFLOW-CTD — ALL ATTACK DETECTORS VERIFICATION")
    print("=" * 70)

    test_port_scan()
    test_syn_flood()
    test_exfiltration()
    test_c2_beaconing()
    test_dga_dns()
    test_tls_anomaly()
    test_detector_engine_e2e()

    print("\n" + "=" * 70)
    print("ALL ATTACK DETECTION TESTS PASSED SUCCESSFULLY! ✓")
    print("=" * 70)


if __name__ == "__main__":
    main()
