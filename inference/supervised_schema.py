import math


SUPERVISED_CLASSES = {
    0: "BENIGN",
    1: "SYN_FLOOD",
    2: "PORT_SCAN",
    3: "C2_BEACONING",
    4: "DGA_DNS_TUNNELLING",
    5: "TLS_METADATA_ANOMALY",
    6: "DATA_EXFILTRATION",
}


SUPERVISED_FEATURE_NAMES = [
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
    "exfil_bytes_sent",
    "exfil_bytes_received",
    "exfil_outbound_inbound_ratio",
    "exfil_bytes_per_second",
    "rolling_unique_destination_ports",
    "rolling_syn_ratio",
    "rolling_flows_per_second",
    "tls_avg_extension_count",
]


SUPERVISED_DEFAULT_VALUES = {
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
    "outbound_inbound_ratio": 1.0,
    "beacon_interval_cv": 1.0,
    "dns_high_entropy_ratio": 0.0,
    "dns_queries_per_second": 0.0,
    "tls_avg_cipher_count": 20.0,
    "tls_missing_sni_ratio": 0.0,
    "exfil_bytes_sent": 0,
    "exfil_bytes_received": 0,
    "exfil_outbound_inbound_ratio": 1.0,
    "exfil_bytes_per_second": 0.0,
    "rolling_unique_destination_ports": 0,
    "rolling_syn_ratio": 0.0,
    "rolling_flows_per_second": 0.0,
    "tls_avg_extension_count": 20.0,
}


def supervised_features_to_vector(features: dict) -> list[float]:
    """Convert combined source features to the supervised model's fixed schema."""
    vector = []
    for name in SUPERVISED_FEATURE_NAMES:
        default = float(SUPERVISED_DEFAULT_VALUES[name])
        value = features.get(name)
        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            numeric_value = default
        if not math.isfinite(numeric_value):
            numeric_value = default
        vector.append(numeric_value)
    return vector
