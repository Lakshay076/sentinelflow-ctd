"""
CTD — API & Frontend Logic Verification Test

Directly tests the route handlers that supply data to the frontend:
- Health & Stats
- Simulation triggers for all 7 threat types
- Active & Historical alert feeds
- Resolve-all functionality
"""

from api.main import root, get_stats, health_check
from api.routes.alerts import (
    get_active_alerts,
    get_alert_history,
    simulate_attack,
    resolve_all_alerts,
    SIMULATION_PRESETS,
)
from api.routes.pcap import (
    get_pcap_files,
    generate_synthetic_pcap,
    replay_pcap_file,
    get_benchmark_status,
    validate_against_ground_truth,
    GeneratePcapRequest,
    ReplayPcapRequest,
)


def test_health():
    res = health_check()
    assert res["status"] == "healthy"
    print("  ✓ health_check() -> healthy")


def test_stats_initial():
    res = get_stats()
    assert "total_alerts" in res
    assert "active_alerts" in res
    print(f"  ✓ get_stats() -> total={res['total_alerts']}, active={res['active_alerts']}")


def test_simulate_all_attacks():
    for attack in SIMULATION_PRESETS.keys():
        payload = simulate_attack(attack_type=attack)
        assert payload["status"] == "simulated"
        assert payload["alert"]["attack_type"] == attack
        print(f"  ✓ simulate_attack('{attack}') -> alert_id={payload['alert']['alert_id']}, severity={payload['alert']['severity']}")


def test_active_and_history():
    active_data = get_active_alerts()
    assert active_data["count"] >= 7, f"Expected >= 7 active alerts, got {active_data['count']}"
    print(f"  ✓ get_active_alerts() -> {active_data['count']} active alerts ready for frontend display")

    hist_data = get_alert_history()
    assert hist_data["count"] >= 7
    print(f"  ✓ get_alert_history() -> {hist_data['count']} history alerts")


def test_resolve_all():
    data = resolve_all_alerts()
    assert data["status"] == "success"
    print(f"  ✓ resolve_all_alerts() -> resolved {data['resolved_count']} alerts")

    res_active_after = get_active_alerts()
    assert res_active_after["count"] == 0
    print("  ✓ get_active_alerts() after resolve -> 0 active alerts")


def test_pcap_endpoints():
    # 1. List files
    files_res = get_pcap_files()
    assert "files" in files_res
    print(f"  ✓ get_pcap_files() -> found {len(files_res['files'])} pcap files")

    # 2. Generate PCAP
    gen_req = GeneratePcapRequest(out="test_api.pcap", attacks=["scan", "syn_flood"])
    gen_res = generate_synthetic_pcap(gen_req)
    assert gen_res["status"] == "success"
    print(f"  ✓ generate_synthetic_pcap() -> generated {gen_res['packet_count']} packets")

    # 3. Replay PCAP
    rep_req = ReplayPcapRequest(pcap_file="test_api.pcap", max_speed=True)
    rep_res = replay_pcap_file(rep_req)
    assert rep_res["status"] == "success"
    bm = rep_res["benchmark"]
    print(f"  ✓ replay_pcap_file() -> {bm['packet_count']} pkts, {bm['sustained_pps']:.1f} pps, {bm['sustained_mbps']:.2f} Mbps")

    # 4. Benchmark status
    bm_res = get_benchmark_status()
    assert bm_res["status"] == "completed"
    print("  ✓ get_benchmark_status() -> benchmark completed verified")

    # 5. Validate against ground truth
    val_res = validate_against_ground_truth(manifest="test_api.pcap.ground_truth.json")
    assert val_res["status"] == "success"
    rep = val_res["report"]
    print(f"  ✓ validate_against_ground_truth() -> TP: {rep['true_positives']}/{rep['expected_attacks']}")


def main():
    print("=" * 70)
    print("SENTINELFLOW-CTD — FRONTEND API & PCAP REPLAY LOGIC TEST SUITE")
    print("=" * 70)

    test_health()
    test_stats_initial()
    print("\nSimulating all 7 attack vectors for frontend dashboard...")
    test_simulate_all_attacks()
    print("\nVerifying Active & History feeds for UI rendering...")
    test_active_and_history()
    print("\nTesting Resolve-All action...")
    test_resolve_all()
    print("\nTesting SIH PCAP Replay & Benchmark Endpoints...")
    test_pcap_endpoints()

    print("\n" + "=" * 70)
    print("ALL API, FRONTEND & PCAP REPLAY DATA FEEDS VERIFIED SUCCESSFULLY! ✓")
    print("=" * 70)


if __name__ == "__main__":
    main()

