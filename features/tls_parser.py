"""
CTD — TLS ClientHello Parser (metadata only)

Parses the TLS ClientHello handshake message directly from
raw bytes, WITHOUT decrypting anything. The ClientHello is
never encrypted -- it is the very first message of a TLS
connection and is always readable by design. It only
contains METADATA about how the connection will be set up
(which encryption options the client offers), never the
actual application data that comes afterward.

This also computes a JA3-style fingerprint: a short hash
that summarizes "how" a TLS client sets up its connection.
Different software (browsers, malware libraries, custom
scripts) tends to produce different, recognizable
fingerprints.

JA3 is a widely used, publicly documented open-source
fingerprinting method. This is a from-scratch, from-first-
principles reimplementation of the published algorithm --
no external JA3 library is required.
"""

import hashlib


# GREASE values are dummy/reserved values that browsers
# insert on purpose, to stop servers from assuming a fixed
# list of ciphers/extensions. JA3 ignores them -- otherwise
# the fingerprint would change randomly on every connection
# from the same browser.
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def _read_uint16(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def parse_client_hello(payload: bytes):
    """
    Parse a raw TCP payload that is expected to start with a
    TLS handshake record containing a ClientHello.

    Returns a dict of extracted fields, or None if this
    payload does not look like a TLS ClientHello (this is
    normal and expected for the vast majority of packets --
    only the very first packet of a TLS connection is a
    ClientHello).
    """

    try:
        # --- TLS record header (5 bytes) ---
        if len(payload) < 9:
            return None

        content_type = payload[0]

        if content_type != 0x16:  # 0x16 = "Handshake" record
            return None

        # --- Handshake header (4 bytes) ---
        handshake_type = payload[5]

        if handshake_type != 0x01:  # 0x01 = "ClientHello"
            return None

        pos = 5 + 4  # skip record header + handshake header

        client_version = _read_uint16(payload, pos)
        pos += 2

        pos += 32  # skip 32-byte "random" field

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
                    # Truncated/incomplete capture -- stop
                    # parsing extensions but keep what we
                    # already found.
                    break

                # Supported groups / elliptic curves (ext 10)
                if ext_type == 10:
                    try:
                        list_len = _read_uint16(
                            payload, ext_data_start
                        )
                        curve_pos = ext_data_start + 2
                        curve_end = curve_pos + list_len
                        while (
                            curve_pos < curve_end
                            and curve_pos + 2 <= len(payload)
                        ):
                            elliptic_curves.append(
                                _read_uint16(payload, curve_pos)
                            )
                            curve_pos += 2
                    except IndexError:
                        pass

                # EC point formats (extension 11)
                if ext_type == 11:
                    try:
                        list_len = payload[ext_data_start]
                        fmt_pos = ext_data_start + 1
                        fmt_end = fmt_pos + list_len
                        while (
                            fmt_pos < fmt_end
                            and fmt_pos < len(payload)
                        ):
                            ec_point_formats.append(
                                payload[fmt_pos]
                            )
                            fmt_pos += 1
                    except IndexError:
                        pass

                # Server Name Indication (extension 0)
                if ext_type == 0:
                    try:
                        name_len = _read_uint16(
                            payload, ext_data_start + 3
                        )
                        name_start = ext_data_start + 5
                        sni = payload[
                            name_start:name_start + name_len
                        ].decode("ascii", errors="ignore")
                    except (IndexError, UnicodeDecodeError):
                        sni = None

                pos = ext_data_end

        return {
            "tls_version": client_version,
            "cipher_suites": cipher_suites,
            "extensions": extensions,
            "elliptic_curves": elliptic_curves,
            "ec_point_formats": ec_point_formats,
            "sni": sni,
        }

    except (IndexError, ValueError):
        # Any malformed/truncated data -> not a ClientHello
        # we can safely parse. Never crash the live pipeline
        # over one odd packet.
        return None


def _filter_grease(values):
    return [v for v in values if v not in GREASE_VALUES]


def compute_ja3(parsed: dict):
    """
    Build the JA3 string and its MD5 hash from a parsed
    ClientHello.

    JA3 string format:
      TLSVersion,Ciphers-Ciphers-...,Extensions-Extensions-...,
      Curves-Curves-...,PointFormats-PointFormats-...
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
