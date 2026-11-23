"""
CTD — TLS ClientHello & ServerHello Parser (Metadata Only)

Parses TLS ClientHello and ServerHello handshake messages directly from
raw bytes WITHOUT decrypting anything. Handshake messages are unencrypted
metadata exchanged to establish the session.

Supported Fingerprinting & Metadata Extractions:
1. JA3: Client fingerprint (TLSVersion,Ciphers,Extensions,Curves,PointFormats).
2. JA3S: Server fingerprint (TLSVersion,Cipher,Extensions).
3. JA4: Standards-compliant FoxIO client fingerprint (JA4_a_JA4_b_JA4_c).
4. QUIC / HTTP3: Passive header extraction (Version, DCID, SCID, Packet Type).

Passive metadata analysis only:
- Zero TLS decryption or MITM proxying.
- Zero QUIC interception or active probing.
"""

import hashlib
import ipaddress
from typing import Dict, List, Optional, Set, Tuple


# GREASE values (RFC 8701) to prevent protocol ossification.
# Ignored during JA3, JA3S, and JA4 calculation.
GREASE_VALUES: Set[int] = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def _read_uint16(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _filter_grease(values: List[int]) -> List[int]:
    return [v for v in values if v not in GREASE_VALUES]


def _is_ip_address(host: Optional[str]) -> bool:
    if not host:
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _map_ja4_version(version_int: int) -> str:
    """Map TLS version uint16 to standard JA4 2-character representation."""
    mapping = {
        0x0304: "13",  # TLS 1.3
        0x0303: "12",  # TLS 1.2
        0x0302: "11",  # TLS 1.1
        0x0301: "10",  # TLS 1.0
        0x0300: "s3",  # SSL 3.0
        0x0200: "s2",  # SSL 2.0
        0x0100: "s1",  # SSL 1.0
    }
    return mapping.get(version_int, "00")


# ---------------------------------------------------------------------
# 1. TLS ClientHello Parser & Fingerprints (JA3 & JA4)
# ---------------------------------------------------------------------

def parse_client_hello(payload: bytes) -> Optional[dict]:
    """
    Parse a raw TCP/UDP payload expected to contain a TLS ClientHello.

    Returns a dict of extracted metadata, or None if the payload
    is not a valid ClientHello.
    """
    try:
        if len(payload) < 9:
            return None

        content_type = payload[0]
        if content_type != 0x16:  # 0x16 = Handshake record
            return None

        handshake_type = payload[5]
        if handshake_type != 0x01:  # 0x01 = ClientHello
            return None

        pos = 5 + 4  # skip 5-byte record header + 4-byte handshake header

        client_version = _read_uint16(payload, pos)
        pos += 2

        pos += 32  # skip 32-byte client random
        if pos >= len(payload):
            return None

        session_id_length = payload[pos]
        pos += 1 + session_id_length

        if pos + 2 > len(payload):
            return None

        cipher_suites_length = _read_uint16(payload, pos)
        pos += 2

        cipher_suites = []
        end = pos + cipher_suites_length
        while pos < end and pos + 2 <= len(payload):
            cipher_suites.append(_read_uint16(payload, pos))
            pos += 2

        if pos >= len(payload):
            return None

        compression_methods_length = payload[pos]
        pos += 1 + compression_methods_length

        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        supported_versions = []
        alpn_protocols = []
        signature_algorithms = []
        sni = None

        if pos + 2 <= len(payload):
            extensions_length = _read_uint16(payload, pos)
            pos += 2
            ext_end = min(pos + extensions_length, len(payload))

            while pos + 4 <= ext_end:
                ext_type = _read_uint16(payload, pos)
                ext_length = _read_uint16(payload, pos + 2)

                ext_data_start = pos + 4
                ext_data_end = ext_data_start + ext_length

                extensions.append(ext_type)

                if ext_data_end > len(payload):
                    break

                # Server Name Indication (SNI - ext 0)
                if ext_type == 0:
                    try:
                        name_len = _read_uint16(payload, ext_data_start + 3)
                        name_start = ext_data_start + 5
                        sni = payload[name_start : name_start + name_len].decode("ascii", errors="ignore")
                    except (IndexError, UnicodeDecodeError):
                        sni = None

                # Supported groups / elliptic curves (ext 10)
                elif ext_type == 10:
                    try:
                        list_len = _read_uint16(payload, ext_data_start)
                        curve_pos = ext_data_start + 2
                        curve_end = curve_pos + list_len
                        while curve_pos < curve_end and curve_pos + 2 <= len(payload):
                            elliptic_curves.append(_read_uint16(payload, curve_pos))
                            curve_pos += 2
                    except IndexError:
                        pass

                # EC point formats (ext 11)
                elif ext_type == 11:
                    try:
                        list_len = payload[ext_data_start]
                        fmt_pos = ext_data_start + 1
                        fmt_end = fmt_pos + list_len
                        while fmt_pos < fmt_end and fmt_pos < len(payload):
                            ec_point_formats.append(payload[fmt_pos])
                            fmt_pos += 1
                    except IndexError:
                        pass

                # Signature algorithms (ext 13)
                elif ext_type == 13:
                    try:
                        sig_list_len = _read_uint16(payload, ext_data_start)
                        s_pos = ext_data_start + 2
                        s_end = s_pos + sig_list_len
                        while s_pos + 2 <= s_end and s_pos + 2 <= len(payload):
                            signature_algorithms.append(_read_uint16(payload, s_pos))
                            s_pos += 2
                    except IndexError:
                        pass

                # ALPN (ext 16)
                elif ext_type == 16:
                    try:
                        alpn_list_len = _read_uint16(payload, ext_data_start)
                        a_pos = ext_data_start + 2
                        a_end = a_pos + alpn_list_len
                        while a_pos < a_end and a_pos < len(payload):
                            proto_len = payload[a_pos]
                            a_pos += 1
                            if a_pos + proto_len <= len(payload):
                                proto = payload[a_pos : a_pos + proto_len].decode("ascii", errors="ignore")
                                alpn_protocols.append(proto)
                                a_pos += proto_len
                            else:
                                break
                    except (IndexError, UnicodeDecodeError):
                        pass

                # Supported versions (ext 43)
                elif ext_type == 43:
                    try:
                        v_len = payload[ext_data_start]
                        v_pos = ext_data_start + 1
                        v_end = v_pos + v_len
                        while v_pos + 2 <= v_end and v_pos + 2 <= len(payload):
                            supported_versions.append(_read_uint16(payload, v_pos))
                            v_pos += 2
                    except IndexError:
                        pass

                pos = ext_data_end

        return {
            "tls_version": client_version,
            "cipher_suites": cipher_suites,
            "extensions": extensions,
            "elliptic_curves": elliptic_curves,
            "ec_point_formats": ec_point_formats,
            "sni": sni,
            "supported_versions": supported_versions,
            "alpn_protocols": alpn_protocols,
            "signature_algorithms": signature_algorithms,
        }

    except (IndexError, ValueError):
        return None


def compute_ja3(parsed: dict) -> Tuple[str, str]:
    """
    Build the JA3 string and its MD5 hash from a parsed ClientHello.

    JA3 string format:
      TLSVersion,Ciphers,Extensions,Curves,PointFormats
    """
    version = parsed["tls_version"]
    ciphers = _filter_grease(parsed["cipher_suites"])
    extensions = _filter_grease(parsed["extensions"])
    curves = _filter_grease(parsed["elliptic_curves"])
    point_formats = parsed["ec_point_formats"]

    ja3_string = "{},{},{},{},{}".format(
        version,
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in extensions),
        "-".join(str(c) for c in curves),
        "-".join(str(p) for p in point_formats),
    )

    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    return ja3_string, ja3_hash


def compute_ja4(parsed: dict, protocol: str = "t") -> Tuple[str, str]:
    """
    Build the standards-compliant FoxIO JA4 fingerprint string and hash.

    Format:
        JA4_a_JA4_b_JA4_c
        Example: t13d1516h2_8daaf6152771_b186095e22b6

    Parameters:
        parsed: Dict returned by parse_client_hello.
        protocol: 't' for TCP, 'q' for QUIC.

    Returns:
        Tuple of (ja4_string, ja4_b_hash).
    """
    # -------------------------------------------------------------
    # Section A (10 characters):
    # protocol (1) + version (2) + sni (1) + cipher_count (2) +
    # extension_count (2) + alpn (2)
    # -------------------------------------------------------------
    # 1. Highest supported TLS version
    versions = _filter_grease(parsed.get("supported_versions", []))
    if versions:
        version_int = max(versions)
    else:
        version_int = parsed.get("tls_version", 0)
    version_str = _map_ja4_version(version_int)

    # 2. SNI: 'd' for domain name, 'i' for IP address or absent
    sni = parsed.get("sni")
    sni_char = "i" if _is_ip_address(sni) else "d"

    # 3. Cipher count (excluding GREASE)
    ciphers = _filter_grease(parsed.get("cipher_suites", []))
    cipher_count = min(len(ciphers), 99)
    cipher_count_str = f"{cipher_count:02d}"

    # 4. Extension count (excluding GREASE)
    extensions = _filter_grease(parsed.get("extensions", []))
    ext_count = min(len(extensions), 99)
    ext_count_str = f"{ext_count:02d}"

    # 5. ALPN: First and last character of first offered ALPN
    alpns = parsed.get("alpn_protocols", [])
    if alpns and alpns[0]:
        first_alpn = alpns[0]
        alpn_str = f"{first_alpn[0]}{first_alpn[-1]}"
    else:
        alpn_str = "00"

    ja4_a = f"{protocol}{version_str}{sni_char}{cipher_count_str}{ext_count_str}{alpn_str}"

    # -------------------------------------------------------------
    # Section B (12 hex characters):
    # SHA-256 hash of sorted 4-character hex cipher suites
    # -------------------------------------------------------------
    if not ciphers:
        ja4_b = "000000000000"
    else:
        sorted_ciphers = sorted(f"{c:04x}" for c in ciphers)
        ciphers_str = ",".join(sorted_ciphers)
        ja4_b = hashlib.sha256(ciphers_str.encode()).hexdigest()[:12]

    # -------------------------------------------------------------
    # Section C (12 hex characters):
    # SHA-256 hash of sorted extensions (excluding GREASE, SNI, ALPN)
    # PLUS original wire-order signature algorithms
    # -------------------------------------------------------------
    c_exts = [e for e in extensions if e not in (0, 16)]  # exclude SNI (0) and ALPN (16)
    sorted_exts = sorted(f"{e:04x}" for e in c_exts)
    ext_str = ",".join(sorted_exts)

    sig_algs = _filter_grease(parsed.get("signature_algorithms", []))
    if 13 in extensions and sig_algs:
        # Signature algorithms in original wire order
        sig_str = ",".join(f"{s:04x}" for s in sig_algs)
        c_combined = f"{ext_str}_{sig_str}" if ext_str else f"_{sig_str}"
    else:
        c_combined = ext_str

    if not c_combined:
        ja4_c = "000000000000"
    else:
        ja4_c = hashlib.sha256(c_combined.encode()).hexdigest()[:12]

    ja4_full = f"{ja4_a}_{ja4_b}_{ja4_c}"
    return ja4_full, ja4_b


# ---------------------------------------------------------------------
# 2. TLS ServerHello Parser & JA3S
# ---------------------------------------------------------------------

def parse_server_hello(payload: bytes) -> Optional[dict]:
    """
    Parse a raw TLS ServerHello handshake message directly from bytes.

    Returns dict containing:
        - tls_version: int
        - selected_cipher: int
        - extensions: List[int]
        - ja3s_string: str
        - ja3s_hash: str
    or None if the payload is not a valid ServerHello.
    """
    try:
        if len(payload) < 38:
            return None

        content_type = payload[0]
        if content_type != 0x16:  # Handshake record
            return None

        handshake_type = payload[5]
        if handshake_type != 0x02:  # ServerHello
            return None

        pos = 5 + 4  # skip 5-byte record header + 4-byte handshake header

        server_version = _read_uint16(payload, pos)
        pos += 2

        pos += 32  # skip 32-byte server random
        if pos >= len(payload):
            return None

        session_id_length = payload[pos]
        pos += 1 + session_id_length

        if pos + 2 > len(payload):
            return None

        selected_cipher = _read_uint16(payload, pos)
        pos += 2

        if pos >= len(payload):
            return None

        compression = payload[pos]
        pos += 1

        extensions = []

        if pos + 2 <= len(payload):
            ext_len = _read_uint16(payload, pos)
            pos += 2
            ext_end = min(pos + ext_len, len(payload))

            while pos + 4 <= ext_end:
                ext_type = _read_uint16(payload, pos)
                ext_data_len = _read_uint16(payload, pos + 2)
                extensions.append(ext_type)

                # In TLS 1.3 ServerHello, supported_versions (ext 43) carries selected version
                if ext_type == 43 and ext_data_len >= 2 and pos + 6 <= len(payload):
                    server_version = _read_uint16(payload, pos + 4)

                pos += 4 + ext_data_len

        # Compute JA3S: TLSVersion,Cipher,Extensions
        ciphers_filtered = _filter_grease([selected_cipher])
        cipher_val = ciphers_filtered[0] if ciphers_filtered else 0
        exts_filtered = _filter_grease(extensions)

        ja3s_string = "{},{},{}".format(
            server_version,
            cipher_val,
            "-".join(str(e) for e in exts_filtered),
        )
        ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()

        return {
            "tls_version": server_version,
            "selected_cipher": selected_cipher,
            "extensions": extensions,
            "ja3s_string": ja3s_string,
            "ja3s_hash": ja3s_hash,
        }

    except (IndexError, ValueError):
        return None


def compute_ja3s(parsed: dict) -> Tuple[str, str]:
    """Helper to return JA3S string and hash from parsed ServerHello."""
    return parsed.get("ja3s_string", ""), parsed.get("ja3s_hash", "")


# ---------------------------------------------------------------------
# 3. Passive QUIC / HTTP3 Metadata Parser
# ---------------------------------------------------------------------

def parse_quic_packet(payload: bytes) -> Optional[dict]:
    """
    Passively parse observable QUIC header and connection metadata (RFC 9000 / RFC 9369).

    Extracts:
    - header_type: 'LONG' or 'SHORT'
    - packet_type: 'INITIAL', '0-RTT', 'HANDSHAKE', 'RETRY', or '1-RTT'
    - version: 32-bit uint32 and hex representation
    - dcid: Destination Connection ID (hex string)
    - scid: Source Connection ID (hex string)
    - client_hello: Parsed ClientHello metadata if observable in Initial packet
    - ja4: Standards-compliant QUIC JA4 fingerprint (e.g. q13...) if ClientHello present
    """
    try:
        if len(payload) < 5:
            return None

        byte_0 = payload[0]
        is_long_header = bool(byte_0 & 0x80)

        if is_long_header:
            version = (payload[1] << 24) | (payload[2] << 16) | (payload[3] << 8) | payload[4]
            packet_type_id = (byte_0 >> 4) & 0x03

            type_mapping = {
                0: "INITIAL",
                1: "0-RTT",
                2: "HANDSHAKE",
                3: "RETRY",
            }
            packet_type = type_mapping.get(packet_type_id, "LONG_UNKNOWN")
            version_hex = f"0x{version:08x}"

            if version == 0x00000001:
                version_name = "QUICv1 (RFC 9000)"
            elif version == 0x6b3343cf:
                version_name = "QUICv2 (RFC 9369)"
            elif version == 0x00000000:
                version_name = "Version Negotiation"
            elif version == 0xff00001d:
                version_name = "draft-29"
            else:
                version_name = f"QUIC-{version_hex}"

            dcil = payload[5]
            if len(payload) < 6 + dcil:
                return None
            dcid = payload[6 : 6 + dcil].hex()

            scil_pos = 6 + dcil
            if len(payload) < scil_pos + 1:
                return None
            scil = payload[scil_pos]

            if len(payload) < scil_pos + 1 + scil:
                return None
            scid = payload[scil_pos + 1 : scil_pos + 1 + scil].hex()

            # Inspect payload for embedded unencrypted ClientHello (CRYPTO frame in Initial packet)
            client_hello = None
            ja4_str = None
            if packet_type == "INITIAL":
                # Look for TLS record marker (0x16 0x03) or Handshake ClientHello (0x01)
                idx = payload.find(b"\x16\x03")
                if idx != -1:
                    client_hello = parse_client_hello(payload[idx:])
                else:
                    # Scan for standalone Handshake ClientHello (0x01 0x00)
                    idx = payload.find(b"\x01\x00")
                    if idx >= 4:
                        # Prepend synthetic 5-byte TLS record header for parse_client_hello
                        fake_header = b"\x16\x03\x03" + int(len(payload) - idx).to_bytes(2, "big")
                        client_hello = parse_client_hello(fake_header + payload[idx:])

                if client_hello:
                    ja4_str, _ = compute_ja4(client_hello, protocol="q")

            return {
                "is_quic": True,
                "header_type": "LONG",
                "packet_type": packet_type,
                "version": version,
                "version_hex": version_hex,
                "version_name": version_name,
                "dcid": dcid,
                "scid": scid,
                "client_hello": client_hello,
                "ja4": ja4_str,
            }

        else:
            # Short Header (1-RTT application data)
            spin_bit = bool(byte_0 & 0x20)
            return {
                "is_quic": True,
                "header_type": "SHORT",
                "packet_type": "1-RTT",
                "spin_bit": spin_bit,
                "version": None,
                "version_hex": None,
                "version_name": "1-RTT Encrypted Application Data",
                "dcid": None,
                "scid": None,
                "client_hello": None,
                "ja4": None,
            }

    except (IndexError, ValueError):
        return None
