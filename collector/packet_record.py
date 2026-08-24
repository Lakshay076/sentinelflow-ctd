from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_length: int
    tcp_flags: Optional[str] = None
