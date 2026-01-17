#!/usr/bin/env python3
"""
RAKSHAK Flow Aggregator
=======================

Converts intercepted packets to network flows for IDS classification.

Features:
- Packet-to-flow aggregation
- CICIDS2017-compatible feature extraction
- Flow timeout handling
- Thread-safe flow management

Author: Team RAKSHAK
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from loguru import logger


@dataclass
class InternalFlow:
    """
    Network flow for internal traffic analysis.

    Compatible with CICIDS2017 feature set for IDS classification.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    duration: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    iat_list: List[float] = field(default_factory=list)
    fwd_pkt_sizes: List[int] = field(default_factory=list)
    bwd_pkt_sizes: List[int] = field(default_factory=list)
    last_packet_time: float = 0.0


class FlowAggregator:
    """
    Aggregate packets into flows for IDS analysis.

    Maintains stateful flow records and extracts features
    compatible with CICIDS2017 dataset for ML-based IDS.
    """

    def __init__(self, flow_timeout: int = 120, min_packets: int = 10):
        """
        Initialize flow aggregator.

        Args:
            flow_timeout: Flow timeout in seconds (default: 120)
            min_packets: Minimum packets before completing flow (default: 10)
        """
        self.flows: Dict[Tuple, InternalFlow] = {}
        self.flow_timeout = flow_timeout
        self.min_packets = min_packets
        self.lock = threading.Lock()
        self.completed_flows = 0
        self.active_flows = 0

        logger.info(f"FlowAggregator initialized (timeout: {flow_timeout}s, min_packets: {min_packets})")

    def add_packet(self, src_ip: str, dst_ip: str,
                   src_port: int, dst_port: int,
                   protocol: str, packet_size: int,
                   tcp_flags: Optional[Dict[str, bool]],
                   timestamp: float) -> Tuple[bool, Optional[dict]]:
        """
        Add packet to flow and return flow if complete.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol (tcp, udp, icmp)
            packet_size: Packet size in bytes
            tcp_flags: TCP flags dict (S, A, F, R, P, U)
            timestamp: Packet timestamp

        Returns:
            Tuple of (flow_complete: bool, flow_data: dict or None)
        """
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        with self.lock:
            # Check if this is forward or backward packet
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                is_forward = True
            elif reverse_key in self.flows:
                flow = self.flows[reverse_key]
                flow_key = reverse_key
                is_forward = False
            else:
                # Create new flow
                flow = InternalFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=timestamp,
                    last_packet_time=timestamp
                )
                self.flows[flow_key] = flow
                self.active_flows = len(self.flows)
                is_forward = True

            # Update flow statistics
            if is_forward:
                flow.fwd_packets += 1
                flow.fwd_bytes += packet_size
                flow.fwd_pkt_sizes.append(packet_size)
            else:
                flow.bwd_packets += 1
                flow.bwd_bytes += packet_size
                flow.bwd_pkt_sizes.append(packet_size)

            # Update inter-arrival time
            if flow.last_packet_time > 0:
                iat = timestamp - flow.last_packet_time
                flow.iat_list.append(iat)

            flow.last_packet_time = timestamp
            flow.duration = timestamp - flow.start_time

            # Update TCP flags
            if tcp_flags:
                if tcp_flags.get('S'): flow.syn_count += 1
                if tcp_flags.get('A'): flow.ack_count += 1
                if tcp_flags.get('F'): flow.fin_count += 1
                if tcp_flags.get('R'): flow.rst_count += 1
                if tcp_flags.get('P'): flow.psh_count += 1
                if tcp_flags.get('U'): flow.urg_count += 1

            # Check if flow is complete
            is_complete = self._is_flow_complete(flow, tcp_flags)

            if is_complete:
                flow_data = self._extract_features(flow)
                del self.flows[flow_key]
                self.completed_flows += 1
                self.active_flows = len(self.flows)

                logger.debug(f"Flow complete: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                            f"({flow.fwd_packets} pkts, {flow.duration:.2f}s)")

                return True, flow_data

        return False, None

    def _is_flow_complete(self, flow: InternalFlow, tcp_flags: Optional[Dict[str, bool]]) -> bool:
        """
        Determine if flow is complete.

        Flow is complete if:
        - Timeout exceeded
        - Minimum packet count reached
        - TCP connection terminated (FIN or RST)
        """
        # Timeout
        if flow.duration >= self.flow_timeout:
            return True

        # Minimum packets
        if flow.fwd_packets + flow.bwd_packets >= self.min_packets:
            return True

        # TCP termination
        if tcp_flags and (tcp_flags.get('F') or tcp_flags.get('R')):
            if flow.fwd_packets + flow.bwd_packets >= 3:  # At least 3 packets
                return True

        return False

    def _extract_features(self, flow: InternalFlow) -> dict:
        """
        Extract CICIDS2017-compatible features from flow.

        Returns:
            Dictionary of flow features
        """
        total_packets = flow.fwd_packets + flow.bwd_packets
        total_bytes = flow.fwd_bytes + flow.bwd_bytes

        # Calculate statistics
        fwd_pkt_len_mean = sum(flow.fwd_pkt_sizes) / len(flow.fwd_pkt_sizes) if flow.fwd_pkt_sizes else 0
        fwd_pkt_len_max = max(flow.fwd_pkt_sizes) if flow.fwd_pkt_sizes else 0
        fwd_pkt_len_min = min(flow.fwd_pkt_sizes) if flow.fwd_pkt_sizes else 0
        fwd_pkt_len_std = self._std(flow.fwd_pkt_sizes)

        bwd_pkt_len_mean = sum(flow.bwd_pkt_sizes) / len(flow.bwd_pkt_sizes) if flow.bwd_pkt_sizes else 0
        bwd_pkt_len_max = max(flow.bwd_pkt_sizes) if flow.bwd_pkt_sizes else 0
        bwd_pkt_len_min = min(flow.bwd_pkt_sizes) if flow.bwd_pkt_sizes else 0
        bwd_pkt_len_std = self._std(flow.bwd_pkt_sizes)

        flow_iat_mean = sum(flow.iat_list) / len(flow.iat_list) if flow.iat_list else 0
        flow_iat_max = max(flow.iat_list) if flow.iat_list else 0
        flow_iat_min = min(flow.iat_list) if flow.iat_list else 0
        flow_iat_std = self._std(flow.iat_list)

        # Calculate flow rate
        flow_packets_per_sec = total_packets / flow.duration if flow.duration > 0 else 0
        flow_bytes_per_sec = total_bytes / flow.duration if flow.duration > 0 else 0

        # Feature vector (compatible with CICIDS2017)
        features = {
            # Basic flow info
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'protocol': flow.protocol,

            # Flow duration and packet counts
            'flow_duration': flow.duration,
            'total_fwd_packets': flow.fwd_packets,
            'total_bwd_packets': flow.bwd_packets,
            'total_length_fwd_packets': flow.fwd_bytes,
            'total_length_bwd_packets': flow.bwd_bytes,

            # Packet length statistics
            'fwd_packet_length_mean': fwd_pkt_len_mean,
            'fwd_packet_length_max': fwd_pkt_len_max,
            'fwd_packet_length_min': fwd_pkt_len_min,
            'fwd_packet_length_std': fwd_pkt_len_std,

            'bwd_packet_length_mean': bwd_pkt_len_mean,
            'bwd_packet_length_max': bwd_pkt_len_max,
            'bwd_packet_length_min': bwd_pkt_len_min,
            'bwd_packet_length_std': bwd_pkt_len_std,

            # Flow IAT statistics
            'flow_iat_mean': flow_iat_mean,
            'flow_iat_max': flow_iat_max,
            'flow_iat_min': flow_iat_min,
            'flow_iat_std': flow_iat_std,

            # TCP flags
            'syn_flag_count': flow.syn_count,
            'ack_flag_count': flow.ack_count,
            'fin_flag_count': flow.fin_count,
            'rst_flag_count': flow.rst_count,
            'psh_flag_count': flow.psh_count,
            'urg_flag_count': flow.urg_count,

            # Flow rates
            'flow_packets_per_sec': flow_packets_per_sec,
            'flow_bytes_per_sec': flow_bytes_per_sec,

            # Timing
            'timestamp': datetime.fromtimestamp(flow.start_time).isoformat(),
        }

        return features

    def _std(self, values: List[float]) -> float:
        """Calculate standard deviation"""
        if not values or len(values) < 2:
            return 0.0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5

    def cleanup_stale_flows(self, max_age: int = 300) -> int:
        """
        Remove stale flows older than max_age seconds.

        Args:
            max_age: Maximum flow age in seconds

        Returns:
            Number of flows removed
        """
        current_time = time.time()
        stale_keys = []

        with self.lock:
            for flow_key, flow in self.flows.items():
                if current_time - flow.last_packet_time > max_age:
                    stale_keys.append(flow_key)

            for key in stale_keys:
                del self.flows[key]

        if stale_keys:
            logger.debug(f"Cleaned up {len(stale_keys)} stale flows")

        self.active_flows = len(self.flows)
        return len(stale_keys)

    def get_statistics(self) -> dict:
        """Get flow aggregator statistics"""
        return {
            "active_flows": self.active_flows,
            "completed_flows": self.completed_flows,
            "flow_timeout": self.flow_timeout,
            "min_packets": self.min_packets
        }
