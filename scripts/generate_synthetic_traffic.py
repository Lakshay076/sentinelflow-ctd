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
    """A handful of internal hosts doing ordinary browsing / DNS."""
    ts = start_ts
    for _ in range(300):
        src = random.choice(INTERNAL_HOSTS)
        dst = random.choice(EXTERNAL_HOSTS)
        sport = random.randint(40000, 60000)

        if random.random() < 0.3:
            # ordinary DNS lookup for a normal-looking domain
            domain = random.choice(
                ["example.com", "mail.example.org", "cdn.example.net", "shop.example.io"]
            )
            pkt = (
                IP(src=src, dst="8.8.8.8")
                / UDP(sport=sport, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=domain))
            )
        else:
            # ordinary TCP handshake-ish traffic with a normal payload size
            flags = "S" if random.random() < 0.2 else "A"
            pkt = (
                IP(src=src, dst=dst)
                / TCP(sport=sport, dport=random.choice([80, 443]), flags=flags)
                / Raw(load=b"x" * random.randint(50, 400))
            )

        ts += random.uniform(0.01, 0.2)
        pkt.time = ts
        packets.append(pkt)

    return ts


def build_port_scan(packets, start_ts):
    """One source fanning out across many destination ports (reconnaissance)."""
    attacker = "10.0.0.50"
    target = random.choice(EXTERNAL_HOSTS)
    ts = start_ts
    for port in range(20, 45):
        pkt = IP(src=attacker, dst=target) / TCP(
            sport=random.randint(40000, 60000), dport=port, flags="S"
        )
        ts += 0.01
        pkt.time = ts
        packets.append(pkt)
    return ts


def build_syn_flood(packets, start_ts):
    """One source sending a high-rate burst of SYNs (volumetric DDoS)."""
    attacker = "10.0.0.51"
    target = random.choice(EXTERNAL_HOSTS)
    ts = start_ts
    for _ in range(120):
        pkt = IP(src=attacker, dst=target) / TCP(
            sport=random.randint(1024, 65000), dport=80, flags="S"
        )
        ts += 0.005  # ~200 SYNs/sec
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
    for _ in range(450):
        pkt = IP(src=attacker, dst=target) / UDP(
            sport=random.randint(1024, 65000), dport=9999
        ) / Raw(load=b"X" * 1400)
        ts += 0.01
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

    for _ in range(6):
        pkt = IP(src=attacker, dst=target) / TCP(
            sport=random.randint(40000, 60000), dport=443, flags="PA"
        ) / Raw(load=client_hello)
        ts += 0.3
        pkt.time = ts
        packets.append(pkt)
    return ts


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic multi-host gateway pcap")
    parser.add_argument(
        "--out", default="synthetic_gateway_traffic.pcap",
        help="Output pcap path (default: synthetic_gateway_traffic.pcap)"
    )
    parser.add_argument(
        "--attacks", nargs="*",
        default=["scan", "syn_flood", "exfil", "beacon", "dga", "tls"],
        help="Which attack patterns to include (default: all)"
    )
    args = parser.parse_args()

    packets = []
    ts = time.time()

    ts = build_normal_traffic(packets, ts, duration_s=30)

    builders = {
        "scan": build_port_scan,
        "syn_flood": build_syn_flood,
        "exfil": build_exfiltration,
        "beacon": build_c2_beaconing,
        "dga": build_dga_dns_tunnelling,
        "tls": build_tls_metadata_anomaly,
    }

    for name in args.attacks:
        if name in builders:
            ts = builders[name](packets, ts + 1.0)

    packets.sort(key=lambda p: p.time)
    wrpcap(args.out, packets)

    # Write a ground-truth manifest alongside the pcap so
    # scripts/validate_detections.py can automatically check
    # whether your pipeline actually caught what it should have.
    attacker_ip_by_attack = {
        "scan": ("10.0.0.50", "PORT_SCAN"),
        "syn_flood": ("10.0.0.51", "SYN_FLOOD"),
        "exfil": ("10.0.0.52", "DATA_EXFILTRATION"),
        "beacon": ("10.0.0.53", "C2_BEACONING"),
        "dga": ("10.0.0.54", "DGA_DNS_TUNNELLING"),
        "tls": ("10.0.0.55", "TLS_METADATA_ANOMALY"),
    }
    ground_truth = {
        "pcap_file": args.out,
        "expected_detections": [
            {"source_ip": ip, "attack_type": attack_type}
            for name, (ip, attack_type) in attacker_ip_by_attack.items()
            if name in args.attacks
        ],
        "benign_ips": INTERNAL_HOSTS,
    }
    gt_path = args.out + ".ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"Wrote {len(packets)} packets to {args.out}")
    print(f"Wrote ground-truth manifest to {gt_path}")
    print(f"Internal hosts simulated : {len(INTERNAL_HOSTS)}")
    print(f"External hosts simulated : {len(EXTERNAL_HOSTS)}")
    print(f"Attack patterns included : {args.attacks}")
    print()
    print("Replay it with:")
    print(f"  python -m collector.pcap_replay_collector {args.out}")
    print("Then validate detection accuracy with:")
    print(f"  python scripts/validate_detections.py {gt_path}")


if __name__ == "__main__":
    main()
