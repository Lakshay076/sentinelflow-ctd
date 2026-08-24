from typing import Dict


def calculate_security_features(features: Dict) -> Dict:
    """
    Convert basic traffic/window features into
    security-oriented derived features.

    This layer does not inspect packet payloads.
    It only operates on metadata already extracted
    by the observation window.
    """

    packets = max(features.get("packets", 0), 1)
    duration = max(features.get("window_duration", 0.0), 0.000001)

    tcp_syn = features.get("tcp_syn", 0)
    tcp_ack = features.get("tcp_ack", 0)
    tcp_rst = features.get("tcp_rst", 0)

    active_flows = features.get("active_flows", 0)
    unique_ports = features.get(
        "unique_destination_ports", 0
    )

    unique_sources = features.get(
        "unique_sources", 0
    )

    unique_destinations = features.get(
        "unique_destinations", 0
    )

    # --------------------------------------------------
    # TCP behavior
    # --------------------------------------------------

    syn_ack_ratio = (
        tcp_syn / max(tcp_ack, 1)
    )

    syn_packet_ratio = (
        tcp_syn / packets
    )

    rst_packet_ratio = (
        tcp_rst / packets
    )

    # --------------------------------------------------
    # Flow behavior
    # --------------------------------------------------

    flow_density = (
        active_flows / packets
    )

    flows_per_second = (
        active_flows / duration
    )

    # --------------------------------------------------
    # Port behavior
    # --------------------------------------------------

    ports_per_source = (
        unique_ports / max(unique_sources, 1)
    )

    ports_per_destination = (
        unique_ports / max(unique_destinations, 1)
    )

    # --------------------------------------------------
    # Traffic diversity
    # --------------------------------------------------

    source_diversity = (
        unique_sources / packets
    )

    destination_diversity = (
        unique_destinations / packets
    )

    # --------------------------------------------------
    # Return security-oriented features
    # --------------------------------------------------

    return {

        "syn_ack_ratio": syn_ack_ratio,

        "syn_packet_ratio": syn_packet_ratio,

        "rst_packet_ratio": rst_packet_ratio,

        "flow_density": flow_density,

        "flows_per_second": flows_per_second,

        "ports_per_source": ports_per_source,

        "ports_per_destination": ports_per_destination,

        "source_diversity": source_diversity,

        "destination_diversity": destination_diversity,
    }
