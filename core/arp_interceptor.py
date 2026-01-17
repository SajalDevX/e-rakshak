#!/usr/bin/env python3
"""
RAKSHAK ARP Interceptor - KAVACH (Shield)
==========================================

Intercepts all device-to-device traffic by positioning RAKSHAK
as the man-in-the-middle for all LAN communications.

This enables:
- Detection of lateral movement attacks
- IDS/IPS for internal traffic
- Honeypot redirection for internal attackers

How it works:
1. RAKSHAK sends gratuitous ARP replies claiming to be every device
2. All devices update their ARP cache: "10.42.0.X is at RAKSHAK's MAC"
3. When attacker tries to reach another device, traffic goes to RAKSHAK first
4. RAKSHAK inspects traffic, then forwards to real destination (or blocks)

Author: Team RAKSHAK
"""

import threading
import time
import subprocess
from typing import Dict, Optional, Callable, List
from dataclasses import dataclass, field
from datetime import datetime

from loguru import logger

# Scapy for ARP operations
try:
    from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - ARP interception disabled")


@dataclass
class InterceptedFlow:
    """Represents an intercepted internal traffic flow."""
    source_ip: str
    source_mac: str
    dest_ip: str
    dest_mac: str
    timestamp: str
    packet_count: int = 0
    bytes_count: int = 0


class ARPInterceptor:
    """
    KAVACH - Positions RAKSHAK as man-in-the-middle for all LAN traffic.

    Sends gratuitous ARP replies to make all devices think
    RAKSHAK is every other device on the network.
    """

    def __init__(self, interface: str, gateway_ip: str,
                 network: str = "10.42.0.0/24",
                 announcement_interval: int = 5,
                 on_internal_traffic: Optional[Callable] = None):
        """
        Initialize ARP Interceptor.

        Args:
            interface: LAN network interface (e.g., enx207bd51a6a7d)
            gateway_ip: Gateway IP address (e.g., 10.42.0.1)
            network: Network CIDR (e.g., 10.42.0.0/24)
            announcement_interval: Seconds between ARP announcements
            on_internal_traffic: Callback when internal traffic is detected
        """
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.network = network
        self.announcement_interval = announcement_interval
        self.on_internal_traffic = on_internal_traffic

        # Get gateway MAC address
        self.gateway_mac = None
        if SCAPY_AVAILABLE:
            try:
                self.gateway_mac = get_if_hwaddr(interface)
            except Exception as e:
                logger.error(f"KAVACH: Failed to get MAC for {interface}: {e}")

        self.running = False
        self.known_devices: Dict[str, str] = {}  # {ip: real_mac}
        self.allowed_pairs: List[tuple] = []  # [(source_ip, dest_ip), ...]
        self._arp_thread: Optional[threading.Thread] = None
        self._stats = {
            "arp_announcements_sent": 0,
            "devices_intercepted": 0,
            "internal_flows_detected": 0
        }

        logger.info(f"KAVACH: Initialized on {interface} (MAC: {self.gateway_mac})")

    def start(self) -> bool:
        """
        Start ARP interception.

        Returns:
            True if started successfully
        """
        if not SCAPY_AVAILABLE:
            logger.error("KAVACH: Cannot start - Scapy not available")
            return False

        if not self.gateway_mac:
            logger.error("KAVACH: Cannot start - no gateway MAC")
            return False

        self.running = True

        # Thread to send periodic ARP announcements
        self._arp_thread = threading.Thread(
            target=self._arp_announcement_loop,
            daemon=True,
            name="KAVACH-ARP"
        )
        self._arp_thread.start()

        logger.info(f"KAVACH: ARP interceptor started on {self.interface}")
        logger.info(f"KAVACH: Gateway {self.gateway_ip} ({self.gateway_mac})")
        return True

    def stop(self):
        """Stop ARP interception and restore real ARP entries."""
        if not self.running:
            return

        self.running = False

        # Wait for thread to finish
        if self._arp_thread and self._arp_thread.is_alive():
            self._arp_thread.join(timeout=2)

        # Restore original ARP entries
        self._restore_arp_tables()
        logger.info("KAVACH: ARP interceptor stopped, ARP tables restored")

    def add_device(self, ip: str, mac: str):
        """
        Register a device for interception.

        Args:
            ip: Device IP address
            mac: Device real MAC address
        """
        if ip == self.gateway_ip:
            return  # Don't intercept ourselves

        if ip not in self.known_devices:
            self.known_devices[ip] = mac
            self._stats["devices_intercepted"] += 1
            logger.info(f"KAVACH: Tracking device {ip} ({mac})")

    def remove_device(self, ip: str):
        """Remove a device from interception."""
        if ip in self.known_devices:
            real_mac = self.known_devices.pop(ip)
            # Restore real ARP for this device
            self._send_restore_arp(ip, real_mac)
            logger.info(f"KAVACH: Stopped tracking {ip}")

    def add_allowed_pair(self, source_ip: str, dest_ip: str):
        """
        Allow direct communication between two devices.

        Used for legitimate services like Chromecast, AirPlay.
        """
        self.allowed_pairs.append((source_ip, dest_ip))
        self.allowed_pairs.append((dest_ip, source_ip))  # Bidirectional
        logger.info(f"KAVACH: Allowed direct communication {source_ip} <-> {dest_ip}")

    def is_pair_allowed(self, source_ip: str, dest_ip: str) -> bool:
        """Check if a device pair is allowed to communicate directly."""
        return (source_ip, dest_ip) in self.allowed_pairs

    def _arp_announcement_loop(self):
        """Continuously announce RAKSHAK as all devices."""
        # Suppress Scapy verbose output
        conf.verb = 0

        # Initial announcement burst
        self._send_all_announcements()

        while self.running:
            try:
                # Send periodic ARP announcements
                self._send_all_announcements()
                time.sleep(self.announcement_interval)

            except Exception as e:
                logger.error(f"KAVACH: ARP announcement error: {e}")
                time.sleep(1)

    def _send_all_announcements(self):
        """Send ARP announcements for all known devices."""
        for target_ip in list(self.known_devices.keys()):
            if target_ip == self.gateway_ip:
                continue

            self._send_gratuitous_arp(target_ip)
            self._stats["arp_announcements_sent"] += 1

    def _send_gratuitous_arp(self, spoofed_ip: str):
        """
        Send gratuitous ARP claiming we are spoofed_ip.

        This makes all devices update their ARP cache:
        "spoofed_ip is at RAKSHAK's MAC"
        """
        try:
            # Gratuitous ARP: "I am spoofed_ip, and my MAC is gateway_mac"
            arp_reply = ARP(
                op="is-at",           # ARP reply
                psrc=spoofed_ip,      # Claim to be this IP
                hwsrc=self.gateway_mac,  # But use our MAC
                pdst=spoofed_ip,      # Target: anyone looking for this IP
                hwdst="ff:ff:ff:ff:ff:ff"  # Broadcast
            )

            ether = Ether(
                dst="ff:ff:ff:ff:ff:ff",  # Broadcast
                src=self.gateway_mac
            )
            packet = ether / arp_reply

            sendp(packet, iface=self.interface, verbose=False)

        except Exception as e:
            logger.debug(f"KAVACH: ARP send error for {spoofed_ip}: {e}")

    def _send_restore_arp(self, ip: str, real_mac: str):
        """Send correct ARP to restore real MAC mapping."""
        try:
            arp_reply = ARP(
                op="is-at",
                psrc=ip,
                hwsrc=real_mac,
                pdst=ip,
                hwdst="ff:ff:ff:ff:ff:ff"
            )

            ether = Ether(
                dst="ff:ff:ff:ff:ff:ff",
                src=real_mac
            )
            packet = ether / arp_reply

            # Send multiple times to ensure propagation
            for _ in range(3):
                sendp(packet, iface=self.interface, verbose=False)
                time.sleep(0.1)

        except Exception as e:
            logger.debug(f"KAVACH: ARP restore error for {ip}: {e}")

    def _restore_arp_tables(self):
        """Restore real ARP entries when shutting down."""
        if not SCAPY_AVAILABLE:
            return

        logger.info("KAVACH: Restoring original ARP entries...")

        for ip, real_mac in list(self.known_devices.items()):
            if ip == self.gateway_ip:
                continue

            self._send_restore_arp(ip, real_mac)

        logger.info("KAVACH: ARP tables restored")

    def handle_intercepted_packet(self, source_ip: str, dest_ip: str,
                                   source_mac: str, dest_mac: str,
                                   protocol: str, dest_port: int) -> bool:
        """
        Handle an intercepted internal packet.

        Called by packet filter when LAN-to-LAN traffic is detected.

        Args:
            source_ip: Source device IP
            dest_ip: Destination device IP
            source_mac: Source device MAC
            dest_mac: Destination device MAC (will be gateway's)
            protocol: Protocol (tcp/udp)
            dest_port: Destination port

        Returns:
            True if packet should be forwarded, False to block
        """
        self._stats["internal_flows_detected"] += 1

        # Check if this pair is allowed
        if self.is_pair_allowed(source_ip, dest_ip):
            logger.debug(f"KAVACH: Allowed internal traffic {source_ip} -> {dest_ip}")
            return True

        # Log the internal connection attempt
        logger.warning(
            f"KAVACH: Internal traffic detected: {source_ip} -> {dest_ip}:{dest_port} ({protocol})"
        )

        # Notify callback if registered
        if self.on_internal_traffic:
            try:
                self.on_internal_traffic({
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "protocol": protocol,
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"KAVACH: Callback error: {e}")

        # Default: allow but flag for monitoring
        # KAAL will decide if it should be blocked
        return True

    def get_statistics(self) -> dict:
        """Get KAVACH statistics."""
        return {
            **self._stats,
            "known_devices": len(self.known_devices),
            "allowed_pairs": len(self.allowed_pairs) // 2,  # Divide by 2 (bidirectional)
            "running": self.running
        }

    def get_known_devices(self) -> Dict[str, str]:
        """Get list of known devices."""
        return self.known_devices.copy()


def create_interceptor_from_config(config: dict) -> Optional[ARPInterceptor]:
    """
    Create ARPInterceptor from RAKSHAK config.

    Args:
        config: RAKSHAK configuration dictionary

    Returns:
        ARPInterceptor instance or None if disabled
    """
    gateway_config = config.get("gateway", {})
    lan_interception = gateway_config.get("lan_interception", {})

    if not lan_interception.get("enabled", False):
        logger.info("KAVACH: LAN interception disabled in config")
        return None

    interface = gateway_config.get("lan_interface", "eth1")
    gateway_ip = gateway_config.get("lan_ip", "10.42.0.1")
    network = gateway_config.get("lan_network", "10.42.0.0/24")
    interval = lan_interception.get("arp_announcement_interval", 5)

    interceptor = ARPInterceptor(
        interface=interface,
        gateway_ip=gateway_ip,
        network=network,
        announcement_interval=interval
    )

    # Add allowed pairs from config
    for pair in lan_interception.get("allowed_pairs", []):
        source = pair.get("source")
        dest = pair.get("dest")
        if source and dest:
            interceptor.add_allowed_pair(source, dest)

    return interceptor
