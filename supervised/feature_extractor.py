"""
SentinelFlow-CTD — Supervised Flow Feature Extractor
====================================================

Extracts the exact 77-feature schema required by the CIC-IDS2017 supervised
classifier from live or replayed network traffic.

Architecture Context & Interaction Design:
------------------------------------------
1. Granularity Distinction:
   - Existing Isolation Forest: Operates on 1-second fixed time windows, aggregating
     16 behavioral features per source IP (packets/s, syn_ratio, unique_ports, etc.).
   - Supervised Threat Classifier: Operates on individual bidirectional flows, requiring
     77 statistical features (IATs, packet length moments, TCP flags, header lengths, etc.)
     consistent with CICFlowMeter / CIC-IDS2017.

2. Interaction Between Window Level and Flow Level:
   - When the Isolation Forest flags an anomaly (ML_ANOMALY) for source IP S,
     SentinelFlow's pipeline queries this module for all candidate flows involving S.
   - For each candidate flow, this extractor computes the exact 77 features in identical
     order to `feature_names.json`.
   - The supervised classifier classifies the flow(s) into one of the 8 threat categories
     (or UNCLASSIFIED if confidence < threshold).
   - The classification result is attached to the incident record, providing explainable
     threat attribution for the ML anomaly without altering Isolation Forest behavior.

Feature Definitions & Units:
----------------------------
- Flow Duration: microseconds (us) = 1e6 * (last_seen - first_seen)
- IAT (Inter-Arrival Time): microseconds (us) between successive packets
- Packet Lengths: bytes (min, max, mean, std, variance)
- Rates: per second (pkts/s, bytes/s) based on flow duration in seconds
- Active / Idle: periods separated by idle threshold (5,000,000 us = 5 seconds)
- Flag Counts: total occurrences of TCP flags (FIN, SYN, RST, PSH, ACK, URG, CWE, ECE)
"""

import math
from typing import Dict, List, Optional, Tuple, Union
import numpy as np


FEATURE_SCHEMA_VERSION = "2.0"

# Exact list of 77 features in alphabetical order, matching artifacts/v2/feature_names.json
FLOW_FEATURE_NAMES: List[str] = [
    "ACK Flag Count",
    "Active Max",
    "Active Mean",
    "Active Min",
    "Active Std",
    "Average Packet Size",
    "Avg Bwd Segment Size",
    "Avg Fwd Segment Size",
    "Bwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Header Length",
    "Bwd IAT Max",
    "Bwd IAT Mean",
    "Bwd IAT Min",
    "Bwd IAT Std",
    "Bwd IAT Total",
    "Bwd PSH Flags",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Min",
    "Bwd Packet Length Std",
    "Bwd Packets/s",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Destination Port",
    "Down/Up Ratio",
    "ECE Flag Count",
    "FIN Flag Count",
    "Flow Bytes/s",
    "Flow Duration",
    "Flow IAT Max",
    "Flow IAT Mean",
    "Flow IAT Min",
    "Flow IAT Std",
    "Flow Packets/s",
    "Fwd Avg Bulk Rate",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Header Length",
    "Fwd IAT Max",
    "Fwd IAT Mean",
    "Fwd IAT Min",
    "Fwd IAT Std",
    "Fwd IAT Total",
    "Fwd PSH Flags",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Min",
    "Fwd Packet Length Std",
    "Fwd Packets/s",
    "Fwd URG Flags",
    "Idle Max",
    "Idle Mean",
    "Idle Min",
    "Idle Std",
    "Init_Win_bytes_backward",
    "Init_Win_bytes_forward",
    "Max Packet Length",
    "Min Packet Length",
    "PSH Flag Count",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "RST Flag Count",
    "SYN Flag Count",
    "Subflow Bwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Fwd Packets",
    "Total Backward Packets",
    "Total Fwd Packets",
    "Total Length of Bwd Packets",
    "Total Length of Fwd Packets",
    "URG Flag Count",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
]

IDLE_THRESHOLD_US = 5_000_000.0  # 5 seconds in microseconds


class FlowFeatureAccumulator:
    """
    Accumulates packets for a single bidirectional flow and computes
    all 77 CIC-IDS2017 features on demand.
    """

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        initiator_ip: Optional[str] = None,
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.upper()

        # The forward direction is defined from initiator -> responder
        self.initiator_ip = initiator_ip or src_ip

        # Timestamps (seconds as float)
        self.all_timestamps: List[float] = []
        self.fwd_timestamps: List[float] = []
        self.bwd_timestamps: List[float] = []

        # Packet total lengths (bytes)
        self.all_lengths: List[int] = []
        self.fwd_lengths: List[int] = []
        self.bwd_lengths: List[int] = []

        # Header lengths (bytes)
        self.fwd_header_lengths: List[int] = []
        self.bwd_header_lengths: List[int] = []

        # Forward data packets (packets with non-zero TCP payload)
        self.act_data_pkt_fwd: int = 0
        self.min_seg_size_forward: int = 32 if self.protocol == "TCP" else 8

        # Initial TCP window sizes
        self.init_win_bytes_fwd: int = 0
        self.init_win_bytes_bwd: int = 0

        # TCP Flag counts
        self.fin_count: int = 0
        self.syn_count: int = 0
        self.rst_count: int = 0
        self.psh_count: int = 0
        self.ack_count: int = 0
        self.urg_count: int = 0
        self.cwe_count: int = 0
        self.ece_count: int = 0

        self.fwd_psh_count: int = 0
        self.bwd_psh_count: int = 0
        self.fwd_urg_count: int = 0
        self.bwd_urg_count: int = 0

    def add_packet(
        self,
        timestamp: float,
        packet_length: int,
        src_ip: str,
        tcp_flags: Optional[str] = None,
        header_length: int = 20,
        payload_length: int = 0,
        window_size: Optional[int] = None,
    ):
        """Add a packet observation to this flow."""
        is_forward = (src_ip == self.initiator_ip)

        self.all_timestamps.append(timestamp)
        self.all_lengths.append(packet_length)

        if is_forward:
            self.fwd_timestamps.append(timestamp)
            self.fwd_lengths.append(packet_length)
            self.fwd_header_lengths.append(header_length)
            if payload_length > 0:
                self.act_data_pkt_fwd += 1
            if header_length > 0:
                self.min_seg_size_forward = min(self.min_seg_size_forward, header_length)
            if window_size is not None and self.init_win_bytes_fwd == 0:
                self.init_win_bytes_fwd = window_size
        else:
            self.bwd_timestamps.append(timestamp)
            self.bwd_lengths.append(packet_length)
            self.bwd_header_lengths.append(header_length)
            if window_size is not None and self.init_win_bytes_bwd == 0:
                self.init_win_bytes_bwd = window_size

        if tcp_flags:
            flags = str(tcp_flags).upper()
            if "F" in flags:
                self.fin_count += 1
            if "S" in flags:
                self.syn_count += 1
            if "R" in flags:
                self.rst_count += 1
            if "P" in flags:
                self.psh_count += 1
                if is_forward:
                    self.fwd_psh_count += 1
                else:
                    self.bwd_psh_count += 1
            if "A" in flags:
                self.ack_count += 1
            if "U" in flags:
                self.urg_count += 1
                if is_forward:
                    self.fwd_urg_count += 1
                else:
                    self.bwd_urg_count += 1
            if "C" in flags:
                self.cwe_count += 1
            if "E" in flags:
                self.ece_count += 1

    @staticmethod
    def _compute_stats(values: List[Union[int, float]]) -> Tuple[float, float, float, float, float]:
        """Returns (min, max, mean, std, variance)."""
        if not values:
            return 0.0, 0.0, 0.0, 0.0, 0.0
        arr = np.array(values, dtype=np.float64)
        min_val = float(np.min(arr))
        max_val = float(np.max(arr))
        mean_val = float(np.mean(arr))
        std_val = float(np.std(arr))
        var_val = float(np.var(arr))
        return min_val, max_val, mean_val, std_val, var_val

    @staticmethod
    def _compute_iats(timestamps: List[float]) -> List[float]:
        """Computes inter-arrival times in microseconds."""
        if len(timestamps) < 2:
            return []
        diffs_sec = np.diff(np.array(timestamps, dtype=np.float64))
        # Ensure non-negative and convert to microseconds
        return [float(max(0.0, d) * 1e6) for d in diffs_sec]

    def _compute_active_idle(self) -> Tuple[List[float], List[float]]:
        """
        Computes active and idle periods in microseconds based on the 5-second threshold.
        """
        if len(self.all_timestamps) < 2:
            return [], []

        active_periods: List[float] = []
        idle_periods: List[float] = []

        cur_active = 0.0
        for i in range(len(self.all_timestamps) - 1):
            diff_us = (self.all_timestamps[i + 1] - self.all_timestamps[i]) * 1e6
            if diff_us >= IDLE_THRESHOLD_US:
                idle_periods.append(diff_us)
                if cur_active > 0:
                    active_periods.append(cur_active)
                    cur_active = 0.0
            else:
                cur_active += diff_us

        if cur_active > 0:
            active_periods.append(cur_active)

        return active_periods, idle_periods

    def extract_features(self) -> Dict[str, float]:
        """
        Compute the complete dictionary of 77 CIC-IDS2017 features.
        """
        total_packets = len(self.all_timestamps)
        fwd_packets = len(self.fwd_timestamps)
        bwd_packets = len(self.bwd_timestamps)

        total_bytes = sum(self.all_lengths)
        fwd_bytes = sum(self.fwd_lengths)
        bwd_bytes = sum(self.bwd_lengths)

        # Flow duration in microseconds
        if total_packets > 1:
            duration_sec = max(0.0, self.all_timestamps[-1] - self.all_timestamps[0])
            flow_duration_us = duration_sec * 1e6
        else:
            duration_sec = 0.0
            flow_duration_us = 0.0

        dur_sec_safe = max(duration_sec, 1e-6)

        # Packet Length Statistics
        p_min, p_max, p_mean, p_std, p_var = self._compute_stats(self.all_lengths)
        f_min, f_max, f_mean, f_std, _ = self._compute_stats(self.fwd_lengths)
        b_min, b_max, b_mean, b_std, _ = self._compute_stats(self.bwd_lengths)

        # Inter-Arrival Times (microseconds)
        flow_iats = self._compute_iats(self.all_timestamps)
        fwd_iats = self._compute_iats(self.fwd_timestamps)
        bwd_iats = self._compute_iats(self.bwd_timestamps)

        flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std, _ = self._compute_stats(flow_iats)
        fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std, _ = self._compute_stats(fwd_iats)
        bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std, _ = self._compute_stats(bwd_iats)

        fwd_iat_total = sum(fwd_iats) if fwd_iats else 0.0
        bwd_iat_total = sum(bwd_iats) if bwd_iats else 0.0

        # Active / Idle
        active_periods, idle_periods = self._compute_active_idle()
        act_min, act_max, act_mean, act_std, _ = self._compute_stats(active_periods)
        idle_min, idle_max, idle_mean, idle_std, _ = self._compute_stats(idle_periods)

        # Flow Rates
        flow_bytes_per_sec = float(total_bytes) / dur_sec_safe
        flow_pkts_per_sec = float(total_packets) / dur_sec_safe
        fwd_pkts_per_sec = float(fwd_packets) / dur_sec_safe
        bwd_pkts_per_sec = float(bwd_packets) / dur_sec_safe

        # Header lengths
        fwd_header_len_total = sum(self.fwd_header_lengths)
        bwd_header_len_total = sum(self.fwd_header_lengths) if not self.bwd_header_lengths else sum(self.bwd_header_lengths)

        down_up_ratio = float(bwd_packets) / max(float(fwd_packets), 1.0)
        avg_packet_size = float(total_bytes) / max(float(total_packets), 1.0)

        # Build feature map
        features: Dict[str, float] = {
            "ACK Flag Count": float(self.ack_count),
            "Active Max": act_max,
            "Active Mean": act_mean,
            "Active Min": act_min,
            "Active Std": act_std,
            "Average Packet Size": avg_packet_size,
            "Avg Bwd Segment Size": b_mean,
            "Avg Fwd Segment Size": f_mean,
            "Bwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Header Length": float(bwd_header_len_total),
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Min": bwd_iat_min,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Total": bwd_iat_total,
            "Bwd PSH Flags": float(self.bwd_psh_count),
            "Bwd Packet Length Max": b_max,
            "Bwd Packet Length Mean": b_mean,
            "Bwd Packet Length Min": b_min,
            "Bwd Packet Length Std": b_std,
            "Bwd Packets/s": bwd_pkts_per_sec,
            "Bwd URG Flags": float(self.bwd_urg_count),
            "CWE Flag Count": float(self.cwe_count),
            "Destination Port": float(self.dst_port),
            "Down/Up Ratio": down_up_ratio,
            "ECE Flag Count": float(self.ece_count),
            "FIN Flag Count": float(self.fin_count),
            "Flow Bytes/s": flow_bytes_per_sec,
            "Flow Duration": flow_duration_us,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Min": flow_iat_min,
            "Flow IAT Std": flow_iat_std,
            "Flow Packets/s": flow_pkts_per_sec,
            "Fwd Avg Bulk Rate": 0.0,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Header Length": float(fwd_header_len_total),
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Min": fwd_iat_min,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Total": fwd_iat_total,
            "Fwd PSH Flags": float(self.fwd_psh_count),
            "Fwd Packet Length Max": f_max,
            "Fwd Packet Length Mean": f_mean,
            "Fwd Packet Length Min": f_min,
            "Fwd Packet Length Std": f_std,
            "Fwd Packets/s": fwd_pkts_per_sec,
            "Fwd URG Flags": float(self.fwd_urg_count),
            "Idle Max": idle_max,
            "Idle Mean": idle_mean,
            "Idle Min": idle_min,
            "Idle Std": idle_std,
            "Init_Win_bytes_backward": float(self.init_win_bytes_bwd),
            "Init_Win_bytes_forward": float(self.init_win_bytes_fwd),
            "Max Packet Length": p_max,
            "Min Packet Length": p_min,
            "PSH Flag Count": float(self.psh_count),
            "Packet Length Mean": p_mean,
            "Packet Length Std": p_std,
            "Packet Length Variance": p_var,
            "RST Flag Count": float(self.rst_count),
            "SYN Flag Count": float(self.syn_count),
            "Subflow Bwd Bytes": float(bwd_bytes),
            "Subflow Bwd Packets": float(bwd_packets),
            "Subflow Fwd Bytes": float(fwd_bytes),
            "Subflow Fwd Packets": float(fwd_packets),
            "Total Backward Packets": float(bwd_packets),
            "Total Fwd Packets": float(fwd_packets),
            "Total Length of Bwd Packets": float(bwd_bytes),
            "Total Length of Fwd Packets": float(fwd_bytes),
            "URG Flag Count": float(self.urg_count),
            "act_data_pkt_fwd": float(self.act_data_pkt_fwd),
            "min_seg_size_forward": float(self.min_seg_size_forward),
        }

        return features

    def to_vector(self, feature_names: Optional[List[str]] = None) -> np.ndarray:
        """
        Return the 77 features as a 1D numpy array in exact schema order.
        """
        names = feature_names or FLOW_FEATURE_NAMES
        fdict = self.extract_features()
        vector = np.array([fdict.get(name, 0.0) for name in names], dtype=np.float32)
        return vector


class LiveFlowTracker:
    """
    Manages flow accumulators for live and replayed traffic.
    Allows retrieval of flow feature vectors by source IP or flow key.
    """

    def __init__(self, timeout_seconds: float = 60.0):
        self.timeout_seconds = timeout_seconds
        # key: (endpoint_a, endpoint_b, protocol) -> FlowFeatureAccumulator
        self.flows: Dict[Tuple, FlowFeatureAccumulator] = {}

    def _get_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> Tuple:
        ea = (src_ip, src_port)
        eb = (dst_ip, dst_port)
        if ea <= eb:
            return (ea, eb, protocol.upper())
        return (eb, ea, protocol.upper())

    def process_packet(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        packet_length: int,
        tcp_flags: Optional[str] = None,
        header_length: int = 20,
        payload_length: int = 0,
        window_size: Optional[int] = None,
    ) -> FlowFeatureAccumulator:
        """Process a packet and update its corresponding flow accumulator."""
        key = self._get_key(src_ip, dst_ip, src_port, dst_port, protocol)

        if key not in self.flows:
            # First packet determines the initiator
            self.flows[key] = FlowFeatureAccumulator(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                initiator_ip=src_ip,
            )

        accumulator = self.flows[key]
        accumulator.add_packet(
            timestamp=timestamp,
            packet_length=packet_length,
            src_ip=src_ip,
            tcp_flags=tcp_flags,
            header_length=header_length,
            payload_length=payload_length,
            window_size=window_size,
        )
        return accumulator

    def get_candidate_flows_for_source(self, source_ip: str) -> List[FlowFeatureAccumulator]:
        """
        Retrieve all active flows initiated by or involving source_ip.
        Used to classify anomalies detected for a source IP.
        """
        candidates = []
        for flow in self.flows.values():
            if flow.initiator_ip == source_ip or flow.src_ip == source_ip:
                candidates.append(flow)
        return candidates

    def get_flow_vectors_for_source(
        self,
        source_ip: str,
        feature_names: Optional[List[str]] = None,
    ) -> List[np.ndarray]:
        """
        Return a list of 77-feature vectors for all active flows of source_ip.
        """
        flows = self.get_candidate_flows_for_source(source_ip)
        return [f.to_vector(feature_names=feature_names) for f in flows]

    def remove_expired(self, current_time: float):
        """Remove flows that have been inactive longer than timeout_seconds."""
        expired_keys = []
        for key, flow in self.flows.items():
            if flow.all_timestamps and (current_time - flow.all_timestamps[-1] > self.timeout_seconds):
                expired_keys.append(key)
        for k in expired_keys:
            del self.flows[k]
