#!/usr/bin/env python3
"""
Port Scan Detector
==================

Detects port scanning attacks through:
- SYN scan detection (multiple ports, short timeframe)
- Network sweep detection (multiple targets)
- Connection attempt rate tracking
- Unusual port access patterns

Detection Patterns:
1. SYN Scan: 10+ ports in 1 minute from same source
2. Network Sweep: 5+ targets in 5 minutes from same source
3. Stealth Scan: FIN/NULL/XMAS scans
4. UDP Scan: Rapid UDP probes

Author: Team RAKSHAK
"""

import time
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
import uuid

from loguru import logger


@dataclass
class ScanAttempt:
    """Individual scan attempt record."""
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    flags: str = ""  # TCP flags


@dataclass
class PortScanEvent:
    """Port scan detection event."""
    event_id: str
    timestamp: datetime
    scanner_ip: str
    scan_type: str  # "syn_scan", "network_sweep", "stealth_scan", "udp_scan"
    ports_scanned: List[int]
    targets_scanned: List[str]
    duration_seconds: float
    severity: str  # "low", "medium", "high", "critical"
    confidence: float
    details: Dict


class PortScanDetector:
    """
    Detects port scanning attacks.

    Features:
    - SYN scan detection (rapid port probing)
    - Network sweep detection (horizontal scanning)
    - Stealth scan detection (FIN/NULL/XMAS)
    - UDP scan detection
    - Automatic response triggering
    """

    # Detection thresholds
    SYN_SCAN_PORT_THRESHOLD = 10  # ports
    SYN_SCAN_TIME_WINDOW = 60  # seconds
    NETWORK_SWEEP_TARGET_THRESHOLD = 5  # targets
    NETWORK_SWEEP_TIME_WINDOW = 300  # seconds (5 minutes)
    UDP_SCAN_THRESHOLD = 20  # rapid UDP probes
    UDP_SCAN_TIME_WINDOW = 30  # seconds

    def __init__(self, config: dict, threat_logger=None):
        """
        Initialize port scan detector.

        Args:
            config: Configuration dictionary
            threat_logger: ThreatLogger instance
        """
        self.config = config
        self.threat_logger = threat_logger

        # Configuration
        scan_config = config.get("enhanced_detection", {}).get("port_scanning", {})
        self.enabled = scan_config.get("enabled", True)
        self.auto_isolate = scan_config.get("auto_isolate_scanner", True)
        self.auto_deploy_honeypot = scan_config.get("auto_deploy_honeypot", True)

        # Scan tracking: src_ip → [ScanAttempt, ...]
        self.scan_tracker: Dict[str, List[ScanAttempt]] = defaultdict(list)

        # Detected scanners (IP → first_detected_time)
        self.detected_scanners: Dict[str, datetime] = {}

        # Detected events
        self.detected_events: List[PortScanEvent] = []
        self.max_events = 1000

        # Statistics
        self.stats = {
            "total_connection_attempts": 0,
            "syn_scans_detected": 0,
            "network_sweeps_detected": 0,
            "stealth_scans_detected": 0,
            "udp_scans_detected": 0,
            "scanners_blocked": 0
        }

        logger.info(f"PortScanDetector initialized (enabled={self.enabled})")

    def process_connection_attempt(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str = "tcp",
        tcp_flags: str = ""
    ) -> Optional[PortScanEvent]:
        """
        Process a connection attempt and check for scanning patterns.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            protocol: Protocol (tcp, udp)
            tcp_flags: TCP flags (SYN, FIN, etc.)

        Returns:
            PortScanEvent if scanning detected, None otherwise
        """
        if not self.enabled:
            return None

        self.stats["total_connection_attempts"] += 1
        current_time = time.time()

        # Create scan attempt record
        attempt = ScanAttempt(
            timestamp=current_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            flags=tcp_flags
        )

        # Add to tracker
        self.scan_tracker[src_ip].append(attempt)

        # Clean old entries
        self._cleanup_old_attempts(src_ip, current_time)

        # Check for scan patterns
        event = None

        if protocol == "tcp":
            # Check for SYN scan
            event = self._check_syn_scan(src_ip, tcp_flags, current_time)
            if event:
                return event

            # Check for stealth scan
            event = self._check_stealth_scan(src_ip, tcp_flags, current_time)
            if event:
                return event

            # Check for network sweep
            event = self._check_network_sweep(src_ip, current_time)
            if event:
                return event

        elif protocol == "udp":
            # Check for UDP scan
            event = self._check_udp_scan(src_ip, current_time)
            if event:
                return event

        return None

    def _check_syn_scan(
        self,
        src_ip: str,
        tcp_flags: str,
        current_time: float
    ) -> Optional[PortScanEvent]:
        """
        Check for SYN scan pattern.

        SYN scan: Many SYN packets to different ports in short time.
        """
        cutoff_time = current_time - self.SYN_SCAN_TIME_WINDOW

        # Filter recent SYN attempts
        recent_syns = [
            attempt for attempt in self.scan_tracker[src_ip]
            if attempt.timestamp > cutoff_time
            and "SYN" in attempt.flags
            and "ACK" not in attempt.flags  # SYN but not SYN-ACK
        ]

        # Count unique ports
        unique_ports = set(attempt.dst_port for attempt in recent_syns)

        if len(unique_ports) >= self.SYN_SCAN_PORT_THRESHOLD:
            logger.warning(
                f"SYN SCAN DETECTED: {src_ip} scanned {len(unique_ports)} ports "
                f"in {self.SYN_SCAN_TIME_WINDOW} seconds"
            )

            # Get target IPs
            targets = list(set(attempt.dst_ip for attempt in recent_syns))

            # Create event
            event = PortScanEvent(
                event_id=f"scan-syn-{uuid.uuid4().hex[:8]}",
                timestamp=datetime.fromtimestamp(current_time),
                scanner_ip=src_ip,
                scan_type="syn_scan",
                ports_scanned=list(unique_ports),
                targets_scanned=targets,
                duration_seconds=self.SYN_SCAN_TIME_WINDOW,
                severity="high",
                confidence=0.90,
                details={
                    "unique_ports": len(unique_ports),
                    "total_attempts": len(recent_syns),
                    "ports": sorted(list(unique_ports))[:20]  # First 20 ports
                }
            )

            self._handle_scan_event(event)
            self.stats["syn_scans_detected"] += 1

            # Clear tracker to avoid repeated alerts
            self.scan_tracker[src_ip] = [
                attempt for attempt in self.scan_tracker[src_ip]
                if attempt.timestamp <= cutoff_time
            ]

            return event

        return None

    def _check_network_sweep(
        self,
        src_ip: str,
        current_time: float
    ) -> Optional[PortScanEvent]:
        """
        Check for network sweep pattern.

        Network sweep: Probing same port across many hosts.
        """
        cutoff_time = current_time - self.NETWORK_SWEEP_TIME_WINDOW

        # Filter recent attempts
        recent_attempts = [
            attempt for attempt in self.scan_tracker[src_ip]
            if attempt.timestamp > cutoff_time
        ]

        # Count unique targets
        unique_targets = set(attempt.dst_ip for attempt in recent_attempts)

        if len(unique_targets) >= self.NETWORK_SWEEP_TARGET_THRESHOLD:
            logger.warning(
                f"NETWORK SWEEP DETECTED: {src_ip} scanned {len(unique_targets)} hosts "
                f"in {self.NETWORK_SWEEP_TIME_WINDOW} seconds"
            )

            # Get common ports
            ports = [attempt.dst_port for attempt in recent_attempts]
            unique_ports = list(set(ports))

            # Create event
            event = PortScanEvent(
                event_id=f"scan-sweep-{uuid.uuid4().hex[:8]}",
                timestamp=datetime.fromtimestamp(current_time),
                scanner_ip=src_ip,
                scan_type="network_sweep",
                ports_scanned=unique_ports,
                targets_scanned=list(unique_targets),
                duration_seconds=self.NETWORK_SWEEP_TIME_WINDOW,
                severity="medium",
                confidence=0.85,
                details={
                    "unique_targets": len(unique_targets),
                    "total_attempts": len(recent_attempts),
                    "most_common_port": max(set(ports), key=ports.count) if ports else 0
                }
            )

            self._handle_scan_event(event)
            self.stats["network_sweeps_detected"] += 1

            # Clear tracker
            self.scan_tracker[src_ip] = [
                attempt for attempt in self.scan_tracker[src_ip]
                if attempt.timestamp <= cutoff_time
            ]

            return event

        return None

    def _check_stealth_scan(
        self,
        src_ip: str,
        tcp_flags: str,
        current_time: float
    ) -> Optional[PortScanEvent]:
        """
        Check for stealth scan patterns (FIN, NULL, XMAS).

        Stealth scans use unusual TCP flags to evade detection.
        """
        # Check for unusual flag combinations
        is_stealth = False
        scan_subtype = ""

        # FIN scan: FIN flag without SYN or ACK
        if "FIN" in tcp_flags and "SYN" not in tcp_flags and "ACK" not in tcp_flags:
            is_stealth = True
            scan_subtype = "FIN"

        # NULL scan: No flags set
        elif not tcp_flags or tcp_flags == "":
            is_stealth = True
            scan_subtype = "NULL"

        # XMAS scan: FIN + URG + PSH flags
        elif "FIN" in tcp_flags and "URG" in tcp_flags and "PSH" in tcp_flags:
            is_stealth = True
            scan_subtype = "XMAS"

        if is_stealth:
            cutoff_time = current_time - self.SYN_SCAN_TIME_WINDOW

            # Count recent stealth attempts
            recent_stealth = [
                attempt for attempt in self.scan_tracker[src_ip]
                if attempt.timestamp > cutoff_time
            ]

            # At least 5 stealth packets = likely scan
            if len(recent_stealth) >= 5:
                logger.warning(
                    f"STEALTH SCAN DETECTED: {src_ip} using {scan_subtype} scan"
                )

                unique_ports = list(set(attempt.dst_port for attempt in recent_stealth))
                targets = list(set(attempt.dst_ip for attempt in recent_stealth))

                event = PortScanEvent(
                    event_id=f"scan-stealth-{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.fromtimestamp(current_time),
                    scanner_ip=src_ip,
                    scan_type=f"stealth_scan_{scan_subtype.lower()}",
                    ports_scanned=unique_ports,
                    targets_scanned=targets,
                    duration_seconds=self.SYN_SCAN_TIME_WINDOW,
                    severity="high",
                    confidence=0.95,
                    details={
                        "scan_subtype": scan_subtype,
                        "tcp_flags": tcp_flags,
                        "unique_ports": len(unique_ports)
                    }
                )

                self._handle_scan_event(event)
                self.stats["stealth_scans_detected"] += 1

                # Clear tracker
                self.scan_tracker[src_ip].clear()

                return event

        return None

    def _check_udp_scan(
        self,
        src_ip: str,
        current_time: float
    ) -> Optional[PortScanEvent]:
        """
        Check for UDP scan pattern.

        UDP scan: Rapid UDP probes to many ports.
        """
        cutoff_time = current_time - self.UDP_SCAN_TIME_WINDOW

        # Filter recent UDP attempts
        recent_udp = [
            attempt for attempt in self.scan_tracker[src_ip]
            if attempt.timestamp > cutoff_time
            and attempt.protocol == "udp"
        ]

        if len(recent_udp) >= self.UDP_SCAN_THRESHOLD:
            logger.warning(
                f"UDP SCAN DETECTED: {src_ip} sent {len(recent_udp)} UDP probes "
                f"in {self.UDP_SCAN_TIME_WINDOW} seconds"
            )

            unique_ports = list(set(attempt.dst_port for attempt in recent_udp))
            targets = list(set(attempt.dst_ip for attempt in recent_udp))

            event = PortScanEvent(
                event_id=f"scan-udp-{uuid.uuid4().hex[:8]}",
                timestamp=datetime.fromtimestamp(current_time),
                scanner_ip=src_ip,
                scan_type="udp_scan",
                ports_scanned=unique_ports,
                targets_scanned=targets,
                duration_seconds=self.UDP_SCAN_TIME_WINDOW,
                severity="medium",
                confidence=0.80,
                details={
                    "total_probes": len(recent_udp),
                    "unique_ports": len(unique_ports)
                }
            )

            self._handle_scan_event(event)
            self.stats["udp_scans_detected"] += 1

            # Clear tracker
            self.scan_tracker[src_ip] = [
                attempt for attempt in self.scan_tracker[src_ip]
                if attempt.timestamp <= cutoff_time
            ]

            return event

        return None

    def _cleanup_old_attempts(self, src_ip: str, current_time: float):
        """Clean up old scan attempts to save memory."""
        # Keep only attempts from last 10 minutes
        cutoff_time = current_time - 600

        self.scan_tracker[src_ip] = [
            attempt for attempt in self.scan_tracker[src_ip]
            if attempt.timestamp > cutoff_time
        ]

        # Remove empty trackers
        if not self.scan_tracker[src_ip]:
            del self.scan_tracker[src_ip]

    def _handle_scan_event(self, event: PortScanEvent):
        """
        Handle detected port scan event.

        Args:
            event: PortScanEvent object
        """
        # Track scanner
        if event.scanner_ip not in self.detected_scanners:
            self.detected_scanners[event.scanner_ip] = event.timestamp

        # Add to detected events
        self.detected_events.append(event)
        if len(self.detected_events) > self.max_events:
            self.detected_events.pop(0)

        # Log to database
        if self.threat_logger:
            try:
                import sqlite3
                from pathlib import Path

                db_path = Path(self.config.get("database", {}).get("path", "data/rakshak.db"))
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()

                ports_str = ",".join(str(p) for p in event.ports_scanned[:50])  # First 50 ports

                cursor.execute("""
                    INSERT INTO port_scan_events (
                        id, timestamp, scanner_ip, ports_scanned, scan_type, action_taken
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.scanner_ip,
                    ports_str,
                    event.scan_type,
                    "isolated" if self.auto_isolate else "logged"
                ))

                conn.commit()
                conn.close()

            except Exception as e:
                logger.error(f"Failed to log port scan event to database: {e}")

        logger.critical(
            f"PORT SCAN EVENT: {event.scan_type} | "
            f"Scanner={event.scanner_ip} | "
            f"Ports={len(event.ports_scanned)} | Targets={len(event.targets_scanned)} | "
            f"Severity={event.severity} | Confidence={event.confidence:.2f}"
        )

    def is_known_scanner(self, ip: str) -> bool:
        """Check if IP is a known scanner."""
        return ip in self.detected_scanners

    def get_recent_events(self, limit: int = 50) -> List[PortScanEvent]:
        """Get recent port scan events."""
        return self.detected_events[-limit:]

    def get_statistics(self) -> dict:
        """Get detection statistics."""
        return self.stats.copy()
