from dataclasses import dataclass, asdict

from flow.flow_engine import Flow


@dataclass
class FlowFeatures:

    duration: float

    total_packets: int
    total_bytes: int

    forward_packets: int
    backward_packets: int

    forward_bytes: int
    backward_bytes: int

    packets_per_second: float
    bytes_per_second: float

    forward_backward_byte_ratio: float


def extract_features(flow: Flow) -> FlowFeatures:

    duration = max(flow.duration(), 0.000001)

    packets_per_second = (
        flow.packets / duration
    )

    bytes_per_second = (
        flow.bytes / duration
    )

    if flow.backward_bytes == 0:

        if flow.forward_bytes > 0:
            byte_ratio = float("inf")
        else:
            byte_ratio = 0.0

    else:

        byte_ratio = (
            flow.forward_bytes /
            flow.backward_bytes
        )

    return FlowFeatures(

        duration=duration,

        total_packets=flow.packets,
        total_bytes=flow.bytes,

        forward_packets=flow.forward_packets,
        backward_packets=flow.backward_packets,

        forward_bytes=flow.forward_bytes,
        backward_bytes=flow.backward_bytes,

        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,

        forward_backward_byte_ratio=byte_ratio
    )


def features_as_dict(flow: Flow):

    features = extract_features(flow)

    return asdict(features)
