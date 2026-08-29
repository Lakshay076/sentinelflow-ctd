"""
CTD — ML Feature Schema

Defines the EXACT list of features (and their order) that
the machine learning model is trained on and later scored
against.

Why this file exists:
    The rule-based detectors each look at only a handful of
    specific features. The ML model instead looks at MANY
    features TOGETHER, to catch combinations of mild
    weirdness that no single rule would flag on its own.

Simple meaning -> Example -> Technical term:
    A row of numbers describing one source's behavior
    -> [12.0, 400.5, 0.1, 3, ...]
    -> "feature vector"

DEFAULT_VALUES matters a lot: most sources will NOT have
DNS or TLS activity in a given window (e.g. a source that
only does plain web browsing has no DNS queries of its
own -- it's just talking to IPs). Missing data should mean
"nothing unusual to report here", not "zero -> suspicious".
So each default is chosen to represent NORMAL/no-signal
behavior for that specific feature, not just 0.
"""

FEATURE_NAMES = [
    "packets_per_second",
    "bytes_per_second",
    "syn_packet_ratio",
    "rst_packet_ratio",
    "unique_destinations",
    "unique_destination_ports",
    "active_flows",
    "flows_per_second",
    "ports_per_destination",
    "bytes_received",
    "outbound_inbound_ratio",
    "beacon_interval_cv",
    "dns_high_entropy_ratio",
    "dns_queries_per_second",
    "tls_avg_cipher_count",
    "tls_missing_sni_ratio",
]


DEFAULT_VALUES = {
    "packets_per_second": 0.0,
    "bytes_per_second": 0.0,
    "syn_packet_ratio": 0.0,
    "rst_packet_ratio": 0.0,
    "unique_destinations": 0,
    "unique_destination_ports": 0,
    "active_flows": 0,
    "flows_per_second": 0.0,
    "ports_per_destination": 0.0,
    "bytes_received": 0,

    # sent == received is a "normal" ratio
    "outbound_inbound_ratio": 1.0,

    # high variation = irregular = normal/human
    "beacon_interval_cv": 1.0,

    "dns_high_entropy_ratio": 0.0,
    "dns_queries_per_second": 0.0,

    # typical real browser cipher suite count
    "tls_avg_cipher_count": 20.0,

    "tls_missing_sni_ratio": 0.0,
}


def features_to_vector(features: dict) -> list:
    """
    Convert a (possibly incomplete) feature dictionary into
    a fixed-length numeric vector, in FEATURE_NAMES order,
    filling in sensible defaults for anything missing.
    """

    return [
        features.get(name, DEFAULT_VALUES[name])
        for name in FEATURE_NAMES
    ]
