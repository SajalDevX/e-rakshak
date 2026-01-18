#!/usr/bin/env python3
"""
Connection Monitor - Passive Port Scan Detection
=================================================

Monitors network connections through system tools to detect port scanning
without requiring nfqueue. Uses:
- iptables LOG rules and kernel log parsing
- /proc/net/tcp for connection tracking
- tcpdump for packet analysis (optional)

This provides an alternative to nfqueue-based inspection that works
reliably across different systems.

Author: Team RAKSHAK
"""

import threading
import time
import re
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Set, List, Optional, Callable
from dataclasses import dataclass
from loguru import logger


@dataclass
class ConnectionAttempt:
    """Represents a connection attempt."""
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    timestamp: datetime
    flags: str = ""


class ConnectionMonitor:
    """
    Monitor network connections to detect port scanning.

    Uses iptables LOG rules and kernel log parsing to detect
    suspicious connection patterns without requiring nfqueue.
    """

    def __init__(self, interface: str = "br0", callback: Optional[Callable] = None):
        """
        Initialize connection monitor.

        Args:
            interface: Network interface to monitor
            callback: Callback function when port scan detected
        """
        self.interface = interface
        self.callback = callback

        # Connection tracking
        self.connections: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.port_attempts: Dict[str, Set[int]] = defaultdict(set)
        self.scan_threshold = 5  # Ports to trigger detection
        self.time_window = 60  # Seconds

        # Monitoring
        self.is_running = False
        self.monitor_thread: Optional[threading.Thread] = None

        # Iptables LOG rule setup
        self.log_prefix = "RAKSHAK_SCAN: "
        self.iptables_setup = False

    def start(self):
        """Start connection monitoring."""
        if self.is_running:
            logger.warning("Connection monitor already running")
            return

        # Setup iptables logging
        self._setup_iptables_logging()

        self.is_running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_kernel_log,
            daemon=True,
            name="ConnectionMonitor"
        )
        self.monitor_thread.start()
        logger.info(f"Connection monitor started on {self.interface}")

    def stop(self):
        """Stop connection monitoring."""
        self.is_running = False

        # Cleanup iptables rules
        self._cleanup_iptables_logging()

        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

        logger.info("Connection monitor stopped")

    def _setup_iptables_logging(self):
        """Setup iptables LOG rules for connection tracking."""
        try:
            # Add rules for both INPUT and FORWARD chains
            # INPUT: catches scans targeting the gateway itself
            # FORWARD: catches scans targeting devices behind the gateway

            for chain in ["INPUT", "FORWARD"]:
                # Check if rule already exists
                check_cmd = [
                    "iptables", "-C", chain,
                    "-i", self.interface,
                    "-p", "tcp",
                    "--tcp-flags", "SYN", "SYN",
                    "-j", "LOG",
                    "--log-prefix", self.log_prefix,
                    "--log-level", "4"
                ]

                result = subprocess.run(check_cmd, capture_output=True, stderr=subprocess.DEVNULL)

                if result.returncode != 0:
                    # Rule doesn't exist, add it
                    add_cmd = [
                        "iptables", "-I", chain, "1",
                        "-i", self.interface,
                        "-p", "tcp",
                        "--tcp-flags", "SYN", "SYN",
                        "-j", "LOG",
                        "--log-prefix", self.log_prefix,
                        "--log-level", "4"
                    ]

                    subprocess.run(add_cmd, check=True, capture_output=True)
                    logger.info(f"Added iptables LOG rule for {chain} chain")

            self.iptables_setup = True

        except subprocess.CalledProcessError as e:
            logger.warning(f"Could not setup iptables logging: {e}")
        except Exception as e:
            logger.error(f"Error setting up iptables logging: {e}")

    def _cleanup_iptables_logging(self):
        """Remove iptables LOG rules."""
        if not self.iptables_setup:
            return

        try:
            # Remove rules from both INPUT and FORWARD chains
            for chain in ["INPUT", "FORWARD"]:
                cmd = [
                    "iptables", "-D", chain,
                    "-i", self.interface,
                    "-p", "tcp",
                    "--tcp-flags", "SYN", "SYN",
                    "-j", "LOG",
                    "--log-prefix", self.log_prefix,
                    "--log-level", "4"
                ]

                subprocess.run(cmd, capture_output=True, stderr=subprocess.DEVNULL)

            logger.info("Removed iptables LOG rules")

        except Exception as e:
            logger.debug(f"Error cleaning up iptables: {e}")

    def _monitor_kernel_log(self):
        """Monitor kernel log for connection attempts."""
        logger.info("Monitoring kernel log for connection attempts...")

        # Pattern to match our LOG entries
        # Example: Jan 18 04:00:00 hostname kernel: RAKSHAK_SCAN: IN=br0 OUT= SRC=10.42.0.103 DST=10.42.0.1 PROTO=TCP SPT=54321 DPT=80
        log_pattern = re.compile(
            r'{}.*SRC=([0-9.]+).*DST=([0-9.]+).*PROTO=(\w+).*DPT=(\d+)'.format(re.escape(self.log_prefix))
        )

        try:
            # Use journalctl to follow kernel messages in real-time
            process = subprocess.Popen(
                ["journalctl", "-k", "-f", "--since", "now"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            )

            for line in iter(process.stdout.readline, ''):
                if not self.is_running:
                    break

                # Parse log line
                match = log_pattern.search(line)
                if match:
                    src_ip = match.group(1)
                    dst_ip = match.group(2)
                    protocol = match.group(3)
                    dst_port = int(match.group(4))

                    # Record connection attempt
                    self._record_connection(src_ip, dst_ip, dst_port, protocol)

            process.terminate()

        except FileNotFoundError:
            # journalctl not available, fall back to dmesg
            logger.warning("journalctl not available, using dmesg fallback")
            self._monitor_dmesg()

        except Exception as e:
            logger.error(f"Error monitoring kernel log: {e}")

    def _monitor_dmesg(self):
        """Fallback: monitor dmesg output."""
        last_line_count = 0

        while self.is_running:
            try:
                # Get recent dmesg output
                result = subprocess.run(
                    ["dmesg", "-T"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                lines = result.stdout.split('\n')

                # Process new lines only
                new_lines = lines[last_line_count:]
                last_line_count = len(lines)

                for line in new_lines:
                    if self.log_prefix in line:
                        # Parse and process
                        match = re.search(
                            r'SRC=([0-9.]+).*DST=([0-9.]+).*PROTO=(\w+).*DPT=(\d+)',
                            line
                        )
                        if match:
                            src_ip = match.group(1)
                            dst_ip = match.group(2)
                            protocol = match.group(3)
                            dst_port = int(match.group(4))

                            self._record_connection(src_ip, dst_ip, dst_port, protocol)

                time.sleep(1)  # Check every second

            except Exception as e:
                logger.debug(f"Error in dmesg monitoring: {e}")
                time.sleep(5)

    def _record_connection(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str):
        """Record a connection attempt and check for port scanning."""
        now = datetime.now()

        # Create connection record
        conn = ConnectionAttempt(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            timestamp=now
        )

        # Track connection
        key = f"{src_ip}->{dst_ip}"
        self.connections[key].append(conn)

        # Track unique ports
        self.port_attempts[src_ip].add(dst_port)

        logger.debug(f"Connection: {src_ip} -> {dst_ip}:{dst_port} ({protocol})")

        # Check for port scan
        self._check_port_scan(src_ip, dst_ip)

    def _check_port_scan(self, src_ip: str, dst_ip: str):
        """Check if source IP is port scanning destination."""
        key = f"{src_ip}->{dst_ip}"
        connections = self.connections[key]

        if len(connections) < self.scan_threshold:
            return

        # Get connections in time window
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.time_window)

        recent_connections = [c for c in connections if c.timestamp >= cutoff]

        if len(recent_connections) < self.scan_threshold:
            return

        # Count unique ports
        unique_ports = set(c.dst_port for c in recent_connections)

        if len(unique_ports) >= self.scan_threshold:
            # Port scan detected!
            logger.warning(
                f"PORT SCAN DETECTED: {src_ip} -> {dst_ip} "
                f"({len(unique_ports)} ports in {self.time_window}s)"
            )

            # Notify callback
            if self.callback:
                scan_info = {
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "attack_type": "port_scan",
                    "severity": "high" if len(unique_ports) > 10 else "medium",
                    "port_count": len(unique_ports),
                    "ports": list(unique_ports)[:20],  # First 20 ports
                    "time_window": self.time_window,
                    "connections": len(recent_connections),
                    "timestamp": now.isoformat()
                }

                try:
                    self.callback(scan_info)
                except Exception as e:
                    logger.error(f"Error in scan detection callback: {e}")

            # Clear to avoid repeated alerts
            self.port_attempts[src_ip].clear()


if __name__ == "__main__":
    # Test the connection monitor
    import sys

    def on_scan_detected(scan_info):
        print(f"\n{'='*60}")
        print(f"PORT SCAN DETECTED!")
        print(f"{'='*60}")
        print(f"Source: {scan_info['source_ip']}")
        print(f"Target: {scan_info['target_ip']}")
        print(f"Ports: {scan_info['port_count']}")
        print(f"Severity: {scan_info['severity']}")
        print(f"{'='*60}\n")

    interface = sys.argv[1] if len(sys.argv) > 1 else "br0"

    monitor = ConnectionMonitor(interface=interface, callback=on_scan_detected)

    print(f"Starting connection monitor on {interface}...")
    print("This requires root privileges to setup iptables rules")
    print("Press Ctrl+C to stop\n")

    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()
