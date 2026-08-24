from dataclasses import dataclass, asdict
from typing import Dict, Tuple

from flow.flow_engine import Flow


@dataclass
class StreamingFeatures:
    """
    Features generated from the current state of a network flow.

    These features are metadata/statistical only.
    No packet payload is inspected.
    """

    flow_id: str

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


class StreamingFeatureEngine:

    def __init__(self):
        self.feature_updates = 0

    def extract(
        self,
        flow_id: str,
        flow: Flow
    ) -> StreamingFeatures:

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

        self.feature_updates += 1

        return StreamingFeatures(

            flow_id=flow_id,

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

    def as_dict(
        self,
        flow_id: str,
        flow: Flow
    ) -> Dict:

        features = self.extract(flow_id, flow)

        return asdict(features)
