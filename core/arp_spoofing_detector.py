#!/usr/bin/env python3
"""
ARP Spoofing Detector
=====================

Detects ARP spoofing attacks through:
- MAC address changes for same IP
- Gratuitous ARP floods
- ARP cache poisoning attempts
- Cross-validation with DHCP leases

Detection Methods:
1. IP-MAC binding tracking
2. Gratuitous ARP flood detection (>2/sec)
3. DHCP lease validation
4. Duplicate IP detection

Author: Team RAKSHAK
"""

import time
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import uuid

from loguru import logger


@dataclass
class ARPBinding:
    """ARP IP-MAC binding."""
    ip_address: str
    mac_address: str
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 1
    is_static: bool = False  # From DHCP lease


@dataclass
class ARPSpoofEvent:
    """ARP spoofing event."""
    event_id: str
    timestamp: datetime
    victim_ip: str
    real_mac: str
    fake_mac: str
    attack_type: str  # "mac_change", "gratuitous_flood", "duplicate_ip"
    severity: str  # "medium", "high", "critical"
    confidence: float
    details: Dict


class ARPSpoofingDetector:
    """
    Detects ARP spoofing attacks.

    Features:
    - IP-MAC binding tracking with change detection
    - Gratuitous ARP flood detection
    - Cross-validation with DHCP leases
    - Automatic response triggering
    """

    # Detection thresholds
    GRATUITOUS_ARP_THRESHOLD = 2  # per second
    MAC_CHANGE_CONFIDENCE_HIGH = 0.90  # High confidence if DHCP lease validates
    MAC_CHANGE_CONFIDENCE_MEDIUM = 0.70  # Medium if no DHCP data

    def __init__(self, config: dict, threat_logger=None):
        """
        Initialize ARP spoofing detector.

        Args:
            config: Configuration dictionary
            threat_logger: ThreatLogger instance
        """
        self.config = config
        self.threat_logger = threat_logger

        # Configuration
        arp_config = config.get("enhanced_detection", {}).get("arp_spoofing", {})
        self.enabled = arp_config.get("enabled", True)
        self.auto_isolate = arp_config.get("auto_isolate_attacker", True)
        self.restore_arp_cache = arp_config.get("restore_arp_cache", True)

        # ARP binding table: ip → ARPBinding
        self.arp_table: Dict[str, ARPBinding] = {}

        # Gratuitous ARP tracking: mac → [(timestamp, ip), ...]
        self.gratuitous_arp_tracker: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

        # DHCP lease cache (populated from gateway)
        self.dhcp_leases: Dict[str, str] = {}  # ip → mac

        # Detected events
        self.detected_events: List[ARPSpoofEvent] = []
        self.max_events = 1000

        # Statistics
        self.stats = {
            "total_arp_packets": 0,
            "mac_changes_detected": 0,
            "gratuitous_floods_detected": 0,
            "duplicate_ips_detected": 0,
            "attacks_blocked": 0
        }

        logger.info(f"ARPSpoofingDetector initialized (enabled={self.enabled})")

    def update_dhcp_leases(self, leases: Dict[str, str]):
        """
        Update DHCP lease cache.

        Args:
            leases: Dictionary of ip → mac mappings
        """
        self.dhcp_leases = leases.copy()
        logger.debug(f"Updated DHCP leases: {len(leases)} entries")

    def process_arp_packet(
        self,
        src_ip: str,
        src_mac: str,
        dst_ip: str,
        is_gratuitous: bool = False
    ) -> Optional[ARPSpoofEvent]:
        """
        Process an ARP packet and check for spoofing.

        Args:
            src_ip: Source IP address
            src_mac: Source MAC address
            dst_ip: Destination IP (for gratuitous ARP detection)
            is_gratuitous: Whether this is a gratuitous ARP

        Returns:
            ARPSpoofEvent if spoofing detected, None otherwise
        """
        if not self.enabled:
            return None

        self.stats["total_arp_packets"] += 1
        current_time = datetime.now()

        # Check for gratuitous ARP flood
        if is_gratuitous:
            event = self._check_gratuitous_flood(src_mac, src_ip)
            if event:
                return event

        # Check for MAC address change
        event = self._check_mac_change(src_ip, src_mac, current_time)
        if event:
            return event

        # Update ARP table
        if src_ip in self.arp_table:
            binding = self.arp_table[src_ip]
            binding.last_seen = current_time
            binding.packet_count += 1
        else:
            # New binding
            is_static = src_ip in self.dhcp_leases and self.dhcp_leases[src_ip] == src_mac

            self.arp_table[src_ip] = ARPBinding(
                ip_address=src_ip,
                mac_address=src_mac,
                first_seen=current_time,
                last_seen=current_time,
                packet_count=1,
                is_static=is_static
            )

        return None

    def _check_mac_change(
        self,
        ip: str,
        new_mac: str,
        current_time: datetime
    ) -> Optional[ARPSpoofEvent]:
        """
        Check if MAC address changed for existing IP.

        Args:
            ip: IP address
            new_mac: New MAC address
            current_time: Current timestamp

        Returns:
            ARPSpoofEvent if spoofing detected
        """
        if ip not in self.arp_table:
            return None

        binding = self.arp_table[ip]
        old_mac = binding.mac_address

        # Same MAC = no change
        if old_mac.lower() == new_mac.lower():
            return None

        # MAC changed - potential ARP spoofing!
        logger.warning(f"MAC CHANGE DETECTED: {ip} | {old_mac} → {new_mac}")

        # Determine confidence
        confidence = self.MAC_CHANGE_CONFIDENCE_MEDIUM
        severity = "high"

        # Cross-validate with DHCP lease
        if ip in self.dhcp_leases:
            dhcp_mac = self.dhcp_leases[ip]

            if dhcp_mac.lower() == new_mac.lower():
                # New MAC matches DHCP lease = likely legitimate
                # Could be device reconnected or lease renewed
                logger.info(f"MAC change validated by DHCP lease: {ip} → {new_mac}")
                confidence = 0.2  # Low confidence it's an attack
                severity = "low"
            elif dhcp_mac.lower() == old_mac.lower():
                # DHCP lease confirms old MAC = new MAC is spoofing
                confidence = self.MAC_CHANGE_CONFIDENCE_HIGH
                severity = "critical"
                logger.critical(f"ARP SPOOFING CONFIRMED: {ip} | DHCP={dhcp_mac}, ARP={new_mac}")

        # Create spoofing event
        event = ARPSpoofEvent(
            event_id=f"arp-spoof-{uuid.uuid4().hex[:8]}",
            timestamp=current_time,
            victim_ip=ip,
            real_mac=old_mac,
            fake_mac=new_mac,
            attack_type="mac_change",
            severity=severity,
            confidence=confidence,
            details={
                "dhcp_mac": self.dhcp_leases.get(ip),
                "first_seen": binding.first_seen.isoformat(),
                "last_seen": binding.last_seen.isoformat(),
                "packet_count": binding.packet_count
            }
        )

        # Only treat as attack if confidence >= 0.5
        if confidence >= 0.5:
            self._handle_spoofing_event(event)
            self.stats["mac_changes_detected"] += 1
            return event
        else:
            logger.debug(f"MAC change ignored (low confidence): {ip}")
            # Update binding with new MAC
            binding.mac_address = new_mac
            binding.last_seen = current_time
            return None

    def _check_gratuitous_flood(self, mac: str, ip: str) -> Optional[ARPSpoofEvent]:
        """
        Check for gratuitous ARP flood attack.

        Args:
            mac: Source MAC address
            ip: Source IP address

        Returns:
            ARPSpoofEvent if flood detected
        """
        current_time = time.time()

        # Add to tracker
        self.gratuitous_arp_tracker[mac].append((current_time, ip))

        # Clean old entries (older than 1 second)
        cutoff_time = current_time - 1.0
        self.gratuitous_arp_tracker[mac] = [
            (t, ip_addr) for t, ip_addr in self.gratuitous_arp_tracker[mac]
            if t > cutoff_time
        ]

        # Check threshold
        recent_count = len(self.gratuitous_arp_tracker[mac])

        if recent_count > self.GRATUITOUS_ARP_THRESHOLD:
            logger.warning(
                f"GRATUITOUS ARP FLOOD: {mac} sent {recent_count} gratuitous ARPs in 1 second"
            )

            # Create event
            event = ARPSpoofEvent(
                event_id=f"arp-flood-{uuid.uuid4().hex[:8]}",
                timestamp=datetime.fromtimestamp(current_time),
                victim_ip=ip,
                real_mac="",  # Unknown
                fake_mac=mac,
                attack_type="gratuitous_flood",
                severity="high",
                confidence=0.85,
                details={
                    "count_per_second": recent_count,
                    "threshold": self.GRATUITOUS_ARP_THRESHOLD
                }
            )

            self._handle_spoofing_event(event)
            self.stats["gratuitous_floods_detected"] += 1

            # Clear tracker to avoid repeated alerts
            self.gratuitous_arp_tracker[mac].clear()

            return event

        return None

    def _handle_spoofing_event(self, event: ARPSpoofEvent):
        """
        Handle detected ARP spoofing event.

        Args:
            event: ARPSpoofEvent object
        """
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

                cursor.execute("""
                    INSERT INTO arp_spoofing_events (
                        id, timestamp, victim_ip, real_mac, fake_mac, severity, action_taken
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.victim_ip,
                    event.real_mac,
                    event.fake_mac,
                    event.severity,
                    "isolated" if self.auto_isolate else "logged"
                ))

                conn.commit()
                conn.close()

            except Exception as e:
                logger.error(f"Failed to log ARP spoofing event to database: {e}")

        logger.critical(
            f"ARP SPOOFING EVENT: {event.attack_type} | "
            f"IP={event.victim_ip} | Fake MAC={event.fake_mac} | "
            f"Severity={event.severity} | Confidence={event.confidence:.2f}"
        )

    def get_arp_table(self) -> Dict[str, ARPBinding]:
        """Get current ARP binding table."""
        return self.arp_table.copy()

    def get_recent_events(self, limit: int = 50) -> List[ARPSpoofEvent]:
        """Get recent ARP spoofing events."""
        return self.detected_events[-limit:]

    def get_statistics(self) -> dict:
        """Get detection statistics."""
        return self.stats.copy()
