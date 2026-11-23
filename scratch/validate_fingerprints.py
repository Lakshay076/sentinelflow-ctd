"""
SentinelFlow-CTD (MONI) -- Independent Fingerprint Validation Suite
Target: NTRO Smart India Hackathon Problem Statement 26145

Validates JA3, JA3S, JA4, and QUIC metadata extraction against
published reference specifications (FoxIO JA4, Salesforce JA3/JA3S, RFC 9000).
"""

import hashlib
import json
import os
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.tls_parser import (
    parse_client_hello,
    parse_server_hello,
    compute_ja3,
    compute_ja3s,
    compute_ja4,
    parse_quic_packet,
    GREASE_VALUES,
)


def run_fingerprint_validation():
    print("=" * 75)
    print("SENTINELFLOW-CTD (MONI) -- INDEPENDENT FINGERPRINT VALIDATION")
    print("=" * 75)

    results = []

    # -------------------------------------------------------------------------
    # TEST 1: JA3 Reference & GREASE Filtering (RFC 8701)
    # -------------------------------------------------------------------------
    print("\n[TEST 1] JA3 & GREASE Filtering:")
    # Synthetic ClientHello payload with GREASE ciphers and extensions
    # Wire order ciphers: [0x0a0a (GREASE), 0x1301 (TLS_AES_128_GCM_SHA256), 0x1302 (TLS_AES_256_GCM_SHA384), 0xc02f]
    # Wire order extensions: [0x1a1a (GREASE), 0x0000 (SNI), 0x000d (sig_algs), 0x002b (supported_versions), 0x0033 (key_share)]
    # Elliptic curves: [0x2a2a (GREASE), 0x001d (x25519), 0x0017 (secp256r1)]
    # Point formats: [0x00 (uncompressed)]

    ciphers = [0x0A0A, 0x1301, 0x1302, 0xC02F]
    extensions = [0x1A1A, 0x0000, 0x000D, 0x002B, 0x0033]
    curves = [0x2A2A, 0x001D, 0x0017]
    point_formats = [0x00]

    raw_ja3, ja3_hash = compute_ja3({
        "tls_version": 0x0303,  # TLS 1.2 record/client version
        "cipher_suites": ciphers,
        "extensions": extensions,
        "elliptic_curves": curves,
        "ec_point_formats": point_formats,
    })

    # Expected: GREASE 0x0a0a, 0x1a1a, 0x2a2a filtered out.
    # 0x1301=4865, 0x1302=4866, 0xc02f=49199
    expected_ciphers = "4865-4866-49199"
    expected_exts = "0-13-43-51"  # 0x0000=0, 0x000d=13, 0x002b=43, 0x0033=51
    expected_curves = "29-23"  # 0x001d=29, 0x0017=23
    expected_points = "0"
    expected_raw_ja3 = f"771,{expected_ciphers},{expected_exts},{expected_curves},{expected_points}"
    expected_ja3_hash = hashlib.md5(expected_raw_ja3.encode()).hexdigest()

    test1_pass = (raw_ja3 == expected_raw_ja3) and (ja3_hash == expected_ja3_hash)
    print(f"  Raw JA3     : {raw_ja3}")
    print(f"  JA3 MD5 Hash: {ja3_hash}")
    print(f"  GREASE removed: 0x0a0a, 0x1a1a, 0x2a2a not present in JA3 string")
    print(f"  Status      : {'PASS' if test1_pass else 'FAIL'}")
    results.append(("JA3 GREASE Filtering & Formatting", test1_pass))

    # -------------------------------------------------------------------------
    # TEST 2: JA3S Reference Validation (ServerHello)
    # -------------------------------------------------------------------------
    print("\n[TEST 2] JA3S Server Fingerprint:")
    # ServerHello: TLS 1.3 negotiated via extension 43 (supported_versions)
    # Record Header (5 bytes): 0x16 0x03 0x03 <len>
    # Handshake Header (4 bytes): 0x02 <len>
    # Server Version: 0x03 0x03 (2 bytes)
    # Random: 32 bytes
    # Session ID: 0 length (1 byte)
    # Selected Cipher: 0x13 0x01 (2 bytes)
    # Compression: 0x00 (1 byte)
    # Extensions Length (2 bytes): 12 bytes
    # Extension 43 (supported_versions, 2 bytes): len=2, value=0x0304 (TLS 1.3) -> 6 bytes
    # Extension 51 (key_share, 2 bytes): len=2, value=0x0000 -> 6 bytes
    sh_extensions = (
        (0x002B).to_bytes(2, "big") + (2).to_bytes(2, "big") + (0x0304).to_bytes(2, "big") +
        (0x0033).to_bytes(2, "big") + (2).to_bytes(2, "big") + (0x0000).to_bytes(2, "big")
    )
    sh_body = (
        (0x0303).to_bytes(2, "big") +
        b"\x00" * 32 +
        b"\x00" +
        (0x1301).to_bytes(2, "big") +
        b"\x00" +
        len(sh_extensions).to_bytes(2, "big") +
        sh_extensions
    )
    hs_msg = bytes([0x02]) + len(sh_body).to_bytes(3, "big") + sh_body
    tls_server_hello_payload = bytes([0x16, 0x03, 0x03]) + len(hs_msg).to_bytes(2, "big") + hs_msg

    parsed_sh = parse_server_hello(tls_server_hello_payload)
    raw_ja3s, ja3s_hash = compute_ja3s(parsed_sh)
    expected_raw_ja3s = "772,4865,43-51"  # 772 is TLS 1.3 (0x0304), 4865 is 0x1301, exts 43 and 51
    expected_ja3s_hash = hashlib.md5(expected_raw_ja3s.encode()).hexdigest()

    test2_pass = (raw_ja3s == expected_raw_ja3s) and (ja3s_hash == expected_ja3s_hash)
    print(f"  Raw JA3S     : {raw_ja3s}")
    print(f"  JA3S MD5 Hash: {ja3s_hash}")
    print(f"  Status       : {'PASS' if test2_pass else 'FAIL'}")
    results.append(("JA3S Server Fingerprint & Version", test2_pass))

    # -------------------------------------------------------------------------
    # TEST 3: FoxIO JA4 Standards Compliance
    # -------------------------------------------------------------------------
    print("\n[TEST 3] FoxIO JA4 Standards Compliance:")
    # Protocol: 't' (TCP)
    # Version: TLS 1.3 ('13')
    # SNI: Domain name present ('d') vs missing ('i')
    # Ciphers: [0x1302, 0x1301, 0x1303, 0xc02b, 0x0a0a (GREASE)] -> count without GREASE = 4
    # Extensions: [0x0000 (SNI), 0x0010 (ALPN), 0x002b, 0x0033, 0x000d (sig_algs)] -> count without GREASE = 5
    # ALPN: 'h2' -> 'h2'
    # Sig algorithms: [0x0403, 0x0804] (ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256)

    ja4_full, ja4_r = compute_ja4(
        {
            "tls_version": 0x0303,
            "supported_versions": [0x0304],
            "sni": "example.com",
            "cipher_suites": [0x1302, 0x1301, 0x1303, 0xC02B, 0x0A0A],
            "extensions": [0x0000, 0x0010, 0x002B, 0x0033, 0x000D],
            "alpn_protocols": ["h2"],
            "signature_algorithms": [0x0403, 0x0804],
        },
        protocol="t",
    )

    # Validate JA4_a:
    # 't' + '13' + 'd' + '04' (4 ciphers) + '05' (5 exts) + 'h2' -> 't13d0405h2'
    expected_ja4_a = "t13d0405h2"
    # Validate JA4_b:
    # Sorted hex ciphers: ['1301', '1302', '1303', 'c02b'] -> comma separated: '1301,1302,1303,c02b'
    # SHA256 first 12 hex chars:
    expected_ja4_b = hashlib.sha256("1301,1302,1303,c02b".encode()).hexdigest()[:12]
    # Validate JA4_c:
    # Sorted extensions excluding SNI (0000) and ALPN (0010): ['000d', '002b', '0033']
    # Sig algs in wire order: ['0403', '0804']
    # Format: "000d,002b,0033_0403,0804"
    # SHA256 first 12 hex chars:
    expected_ja4_c = hashlib.sha256("000d,002b,0033_0403,0804".encode()).hexdigest()[:12]

    expected_ja4_full = f"{expected_ja4_a}_{expected_ja4_b}_{expected_ja4_c}"

    test3_pass = (ja4_full == expected_ja4_full)
    print(f"  Generated JA4: {ja4_full}")
    print(f"  Expected JA4 : {expected_ja4_full}")
    print(f"  JA4_a Match  : {ja4_full.startswith(expected_ja4_a)}")
    print(f"  JA4_b Match  : {ja4_full.split('_')[1] == expected_ja4_b}")
    print(f"  JA4_c Match  : {ja4_full.split('_')[2] == expected_ja4_c}")
    print(f"  Status       : {'PASS' if test3_pass else 'FAIL'}")
    results.append(("FoxIO JA4 Calculation & Structure", test3_pass))

    # -------------------------------------------------------------------------
    # TEST 4: JA4 Variations (No SNI, No ALPN, TLS 1.2)
    # -------------------------------------------------------------------------
    print("\n[TEST 4] JA4 Edge Cases (Missing SNI, HTTP/1.1 ALPN, TLS 1.2):")
    ja4_nosni, _ = compute_ja4(
        {
            "tls_version": 0x0303,
            "supported_versions": [],
            "sni": None,
            "cipher_suites": [0xC02F, 0xC030],
            "extensions": [0x000D, 0x0010],
            "alpn_protocols": ["http/1.1"],
            "signature_algorithms": [0x0401],
        },
        protocol="t",
    )
    # Expected JA4_a: 't' + '12' + 'i' + '02' + '02' + 'h1' -> 't12i0202h1'
    test4_pass = ja4_nosni.startswith("t12i0202h1")
    print(f"  No-SNI + HTTP/1.1 JA4: {ja4_nosni}")
    print(f"  JA4_a expected: 't12i0202h1', got: {ja4_nosni[:10]}")
    print(f"  Status               : {'PASS' if test4_pass else 'FAIL'}")
    results.append(("JA4 Edge Cases (No SNI, HTTP/1.1, TLS 1.2)", test4_pass))

    # -------------------------------------------------------------------------
    # TEST 5: QUIC RFC 9000 Metadata Extraction
    # -------------------------------------------------------------------------
    print("\n[TEST 5] QUIC RFC 9000 Passive Metadata Extraction:")
    # Construct synthetic QUIC Long Header Initial packet (RFC 9000 section 17.2.2)
    # Header Byte: 0xC0 (Header Form=1, Fixed Bit=1, Long Packet Type=0 (Initial))
    # Version: 0x00000001 (QUIC v1)
    # DCID Len: 0x08, DCID: 8 bytes
    # SCID Len: 0x08, SCID: 8 bytes
    # Token Len: 0x00
    # Length: 0x10
    quic_long_initial = (
        bytes([0xC0]) +
        (0x00000001).to_bytes(4, "big") +
        bytes([8]) + bytes.fromhex("0102030405060708") +
        bytes([8]) + bytes.fromhex("090A0B0C0D0E0F10") +
        bytes([0]) +
        bytes([16]) +
        b"\x00" * 16
    )

    quic_meta = parse_quic_packet(quic_long_initial)
    test5_pass = (
        quic_meta is not None
        and quic_meta.get("is_quic") is True
        and quic_meta.get("header_type") == "LONG"
        and quic_meta.get("packet_type") == "INITIAL"
        and quic_meta.get("version_hex") == "0x00000001"
        and quic_meta.get("dcid") == "0102030405060708"
        and quic_meta.get("scid") == "090a0b0c0d0e0f10"
    )
    print(f"  Is QUIC         : {quic_meta.get('is_quic')}")
    print(f"  Header Type     : {quic_meta.get('header_type')}")
    print(f"  Packet Type     : {quic_meta.get('packet_type')}")
    print(f"  Version         : {quic_meta.get('version_hex')} ({quic_meta.get('version_name')})")
    print(f"  DCID            : {quic_meta.get('dcid')}")
    print(f"  SCID            : {quic_meta.get('scid')}")
    print(f"  Status          : {'PASS' if test5_pass else 'FAIL'}")
    results.append(("QUIC Initial Long Header Metadata (RFC 9000)", test5_pass))

    # -------------------------------------------------------------------------
    # TEST 6: QUIC Short Header (1-RTT) Encryption Boundary
    # -------------------------------------------------------------------------
    print("\n[TEST 6] QUIC 1-RTT Short Header Boundary:")
    # Short header: Header byte = 0x40 (Header Form=0, Fixed Bit=1)
    # 1-RTT application packets are encrypted; passive sensor cannot decrypt frames.
    quic_short = bytes([0x40]) + bytes.fromhex("1122334455667788") + b"\xff" * 20
    quic_short_meta = parse_quic_packet(quic_short)
    test6_pass = (
        quic_short_meta is not None
        and quic_short_meta.get("is_quic") is True
        and quic_short_meta.get("header_type") == "SHORT"
        and quic_short_meta.get("packet_type") == "1-RTT"
        and quic_short_meta.get("client_hello") is None  # Cannot decrypt 1-RTT
        and quic_short_meta.get("ja4") is None
    )
    print(f"  Is QUIC         : {quic_short_meta.get('is_quic')}")
    print(f"  Header Type     : {quic_short_meta.get('header_type')}")
    print(f"  Packet Type     : {quic_short_meta.get('packet_type')}")
    print(f"  ClientHello Seen: {quic_short_meta.get('client_hello')} (Correctly acknowledges encryption)")
    print(f"  Status          : {'PASS' if test6_pass else 'FAIL'}")
    results.append(("QUIC 1-RTT Encryption Boundary Verification", test6_pass))

    print("\n" + "=" * 75)
    print("FINGERPRINT VALIDATION SUMMARY")
    print("=" * 75)
    all_ok = True
    for name, status in results:
        print(f"  {name:<50}: {'PASS' if status else 'FAIL'}")
        if not status:
            all_ok = False
    print("=" * 75)
    print(f"Overall Status: {'ALL 6 TESTS PASSED' if all_ok else 'SOME TESTS FAILED'}\n")
    return all_ok


if __name__ == "__main__":
    success = run_fingerprint_validation()
    sys.exit(0 if success else 1)
