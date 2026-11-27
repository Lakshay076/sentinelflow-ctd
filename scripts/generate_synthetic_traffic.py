"""
CTD -- Synthetic Multi-Host Gateway Traffic Generator

The SIH problem statement expects a "simulated IP data" stream
representing a gateway/peering link -- i.e. MANY internal hosts
talking to MANY external hosts, not one laptop's own traffic.

This script builds that directly with Scapy (no network access,
no sniffing) and writes it to a .pcap file:

  - A pool of "internal" source IPs (simulating hosts behind the
    monitored gateway) doing ordinary browsing/DNS traffic.
  - One embedded attack pattern per threat class in the SIH brief,
    each launched from its own source IP so detectors can be
    evaluated per-class:
        PORT_SCAN            -> fan-out across many dest ports
        SYN_FLOOD            -> high-rate spoofed-looking SYNs
        UDP_FLOOD            -> high-rate single-source UDP flood
        DISTRIBUTED_UDP_FLOOD -> high-entropy spoofed-source UDP flood
        DATA_EXFILTRATION    -> large asymmetric outbound burst
        C2_BEACONING         -> fixed-interval repeated check-ins
        DGA_DNS_TUNNELLING   -> high-entropy DNS query names
        TLS_METADATA_ANOMALY -> minimal/no-SNI TLS ClientHellos

Output: a .pcap file you feed into the pcap-replay collector:
    python -m collector.pcap_replay_collector synthetic_gateway_traffic.pcap

This is placeholder/demo data -- for the real SIH deliverable,
prefer real or public-dataset traffic (see docs/SIH_ALIGNMENT.md)
and reserve this generator for quick pipeline smoke-testing.
"""

import argparse
import json
import random
import string
import time

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

random.seed(42)

INTERNAL_HOSTS = [f"10.0.0.{i}" for i in range(10, 30)]       # simulated internal LAN
EXTERNAL_HOSTS = [f"203.0.113.{i}" for i in range(1, 40)]      # simulated internet hosts
GATEWAY_EXT_IP = "198.51.100.9"                                # a "normal" external server


def build_normal_traffic(packets, start_ts, duration_s):
    """Simulate internal hosts doing ordinary bidirectional browsing and DNS."""
    ts = start_ts
    for _ in range(150):
        src = random.choice(INTERNAL_HOSTS)
        dst = random.choice(EXTERNAL_HOSTS)
        sport = random.randint(40000, 60000)

        if random.random() < 0.3:
            # ordinary DNS lookup and UDP DNS response
            domain = random.choice(
                ["example.com", "mail.example.org", "cdn.example.net", "shop.example.io"]
            )
            pkt = (
                IP(src=src, dst="8.8.8.8")
                / UDP(sport=sport, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=domain))
            )
            ts += random.uniform(0.05, 0.25)
            pkt.time = ts
            packets.append(pkt)

            resp = (
                IP(src="8.8.8.8", dst=src)
                / UDP(sport=53, dport=sport)
                / DNS(qr=1, qd=DNSQR(qname=domain))
                / Raw(load=b"R" * random.randint(60, 140))
            )
            ts += random.uniform(0.005, 0.02)
            resp.time = ts
            packets.append(resp)
        else:
            # ordinary TCP connection/request paired with server reply bytes
            dport = random.choice([80, 443])
            flags = "S" if random.random() < 0.2 else "A"
            pkt = (
                IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags=flags)
                / Raw(load=b"x" * random.randint(50, 250))
            )
            ts += random.uniform(0.05, 0.25)
            pkt.time = ts
            packets.append(pkt)

            resp_flags = "SA" if flags == "S" else "PA"
            resp = (
                IP(src=dst, dst=src)
                / TCP(sport=dport, dport=sport, flags=resp_flags)
                / Raw(load=b"y" * random.randint(300, 900))
            )
            ts += random.uniform(0.005, 0.03)
            resp.time = ts
            packets.append(resp)

    return ts


def build_port_scan(packets, start_ts):
    """One source fanning out across many destination ports (reconnaissance)."""
    attacker = "10.0.0.50"
    target = random.choice(EXTERNAL_HOSTS)
    ts = start_ts
    scan_intervals = [0.01, 0.018, 0.012, 0.027, 0.009]
    for i, port in enumerate(range(20, 45)):
        pkt = IP(src=attacker, dst=target) / TCP(
            sport=random.randint(40000, 60000), dport=port, flags="S"
        )
        ts += scan_intervals[i % len(scan_intervals)]
        pkt.time = ts
        packets.append(pkt)
    return ts


def build_syn_flood(packets, start_ts):
    """One source sending a high-rate burst of SYNs (volumetric DDoS)."""
    attacker = "10.0.0.51"
    target = random.choice(EXTERNAL_HOSTS)
    ts = start_ts
    flood_intervals = [0.004, 0.006, 0.003, 0.005, 0.004]
    flood_sport = 51000

    for i in range(120):
        pkt = IP(src=attacker, dst=target) / TCP(
            sport=flood_sport, dport=80, flags="S"
        )
        ts += flood_intervals[i % len(flood_intervals)]
        pkt.time = ts
        packets.append(pkt)
    return ts


def build_exfiltration(packets, start_ts):
    """One source sending a large one-way outbound burst (asymmetric byte ratio)."""
    attacker = "10.0.0.52"
    target = random.choice(EXTERNAL_HOSTS)
    ts = start_ts
    # 450 x 1400 bytes = ~630KB, comfortably over the 500KB /
    # asymmetric-ratio thresholds the exfiltration detector checks.
    exfil_intervals = [0.007, 0.013, 0.009, 0.018, 0.011]
    exfil_sport = 52000

    for i in range(450):
        pkt = IP(src=attacker, dst=target) / UDP(
            sport=exfil_sport, dport=9999
        ) / Raw(load=b"X" * 1400)
        ts += exfil_intervals[i % len(exfil_intervals)]
        pkt.time = ts
        packets.append(pkt)
    return ts


def build_c2_beaconing(packets, start_ts):
    """One source checking in at a suspiciously exact fixed interval."""
    attacker = "10.0.0.53"
    c2_server = random.choice(EXTERNAL_HOSTS)
    ts = start_ts
    for _ in range(6):
        pkt = IP(src=attacker, dst=c2_server) / TCP(
            sport=random.randint(40000, 60000), dport=443, flags="S"
        )
        ts += 5.0  # exact 5.0s interval every time -> low coefficient of variation
        pkt.time = ts
        packets.append(pkt)
    return ts


def build_dga_dns_tunnelling(packets, start_ts):
    """One source firing high-entropy, unusually long DNS query names."""
    attacker = "10.0.0.54"
    ts = start_ts
    for _ in range(10):
        random_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=42))
        domain = f"{random_label}.tunnel.example"
        pkt = IP(src=attacker, dst="8.8.8.8") / UDP(
            sport=random.randint(40000, 60000), dport=53
        ) / DNS(rd=1, qd=DNSQR(qname=domain))
        ts += 0.15
        pkt.time = ts
        packets.append(pkt)
    return ts


def build_tls_metadata_anomaly(packets, start_ts):
    """One source sending minimal TLS ClientHellos with no SNI (non-browser-like)."""
    attacker = "10.0.0.55"
    target = random.choice(EXTERNAL_HOSTS)
    ts = start_ts

    # Minimal, hand-built ClientHello-shaped bytes: enough for tls_parser to
    # see "few ciphers, no SNI extension" without a real TLS library.
    # (Matches the shape parse_client_hello expects: handshake type 0x16 0x01)
    client_hello = bytes([
        0x16, 0x03, 0x01, 0x00, 0x2f,        # TLS record header
        0x01, 0x00, 0x00, 0x2b,              # Handshake: ClientHello
        0x03, 0x03,                          # TLS 1.2
    ]) + b"\x00" * 32 + bytes([0x00]) + bytes([0x00, 0x02, 0x00, 0x2f]) + bytes([0x01, 0x00])

    tls_intervals = [0.3, 1.1, 0.5, 1.7, 0.8, 1.4]

    for i in range(6):
        pkt = IP(src=attacker, dst=target) / TCP(
            sport=random.randint(40000, 60000), dport=443, flags="PA"
        ) / Raw(load=client_hello)
        ts += tls_intervals[i]
        pkt.time = ts
        packets.append(pkt)
    return ts


def build_udp_flood(packets, start_ts):
    """One source sending a concentrated high-rate UDP flood."""
    attacker = "10.0.0.56"
    target = random.choice(EXTERNAL_HOSTS)
    ts = start_ts
    payload = b"U" * 128

    for i in range(400):
        pkt = (
            IP(src=attacker, dst=target)
            / UDP(sport=20000 + (i % 1000), dport=53)
            / Raw(load=payload)
        )
        ts += 0.001
        pkt.time = ts
        packets.append(pkt)
    return ts


def build_distributed_udp_flood(packets, start_ts):
    """Multiple spoofed sources sending a distributed high-entropy UDP flood."""
    target = random.choice(EXTERNAL_HOSTS)
    ts = start_ts
    payload = b"D" * 512

    # 120 packets distributed uniformly across 15 spoofed sources (8 pkts/source)
    for i in range(120):
        src_ip = f"10.88.{(i % 15) + 1}.1"
        pkt = (
            IP(src=src_ip, dst=target)
            / UDP(sport=21000 + (i % 1000), dport=53)
            / Raw(load=payload)
        )
        ts += 0.003
        pkt.time = ts
        packets.append(pkt)
    return ts


DEFAULT_ATTACKS = [
    "scan",
    "syn_flood",
    "udp_flood",
    "distributed_udp_flood",
    "exfil",
    "beacon",
    "dga",
    "tls",
]

ATTACK_BUILDERS = {
    "scan": build_port_scan,
    "syn_flood": build_syn_flood,
    "udp_flood": build_udp_flood,
    "distributed_udp_flood": build_distributed_udp_flood,
    "exfil": build_exfiltration,
    "beacon": build_c2_beaconing,
    "dga": build_dga_dns_tunnelling,
    "tls": build_tls_metadata_anomaly,
}

ATTACKER_IP_BY_ATTACK = {
    "scan": ("10.0.0.50", "PORT_SCAN"),
    "syn_flood": ("10.0.0.51", "SYN_FLOOD"),
    "udp_flood": ("10.0.0.56", "UDP_FLOOD"),
    "distributed_udp_flood": ("__NETWORK__", "DISTRIBUTED_UDP_FLOOD"),
    "exfil": ("10.0.0.52", "DATA_EXFILTRATION"),
    "beacon": ("10.0.0.53", "C2_BEACONING"),
    "dga": ("10.0.0.54", "DGA_DNS_TUNNELLING"),
    "tls": ("10.0.0.55", "TLS_METADATA_ANOMALY"),
}


def generate_synthetic_pcap_file(out_path: str, attacks=None, pcap_label=None) -> dict:
    """Generate a synthetic gateway PCAP and matching ground-truth manifest."""
    selected_attacks = list(attacks) if attacks is not None else list(DEFAULT_ATTACKS)

    packets = []
    ts = time.time()
    ts = build_normal_traffic(packets, ts, duration_s=30)

    for name in selected_attacks:
        builder = ATTACK_BUILDERS.get(name)
        if builder is not None:
            ts = builder(packets, ts + 1.0)

    packets.sort(key=lambda p: p.time)
    wrpcap(out_path, packets)

    ground_truth = {
        "pcap_file": pcap_label if pcap_label is not None else out_path,
        "expected_detections": [
            {"source_ip": ip, "attack_type": attack_type}
            for name, (ip, attack_type) in ATTACKER_IP_BY_ATTACK.items()
            if name in selected_attacks
        ],
        "benign_ips": INTERNAL_HOSTS,
    }
    gt_path = out_path + ".ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump(ground_truth, f, indent=2)

    return {
        "packet_count": len(packets),
        "gt_path": gt_path,
        "ground_truth": ground_truth,
        "attacks_included": selected_attacks,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic multi-host gateway pcap")
    parser.add_argument(
        "--out", default="synthetic_gateway_traffic.pcap",
        help="Output pcap path (default: synthetic_gateway_traffic.pcap)"
    )
    parser.add_argument(
        "--attacks", nargs="*",
        default=list(DEFAULT_ATTACKS),
        help="Which attack patterns to include (default: all)"
    )
    args = parser.parse_args()

    result = generate_synthetic_pcap_file(args.out, attacks=args.attacks, pcap_label=args.out)

    print(f"Wrote {result['packet_count']} packets to {args.out}")
    print(f"Wrote ground-truth manifest to {result['gt_path']}")
    print(f"Internal hosts simulated : {len(INTERNAL_HOSTS)}")
    print(f"External hosts simulated : {len(EXTERNAL_HOSTS)}")
    print(f"Attack patterns included : {result['attacks_included']}")
    print()
    print("Replay it with:")
    print(f"  python -m collector.pcap_replay_collector {args.out}")
    print("Then validate detection accuracy with:")
    print(f"  python scripts/validate_detections.py {gt_path}")


if __name__ == "__main__":
    main()
