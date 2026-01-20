#!/usr/bin/env python3
"""
RAKSHAK Trust Manager
=====================

Zero Trust device enrollment and zone assignment module.

Features:
- Device enrollment workflow
- Zone-based network segmentation
- Trust state management
- Audit logging

Author: Team RAKSHAK
"""

import sqlite3
import ipaddress
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass

from loguru import logger


@dataclass
class TrustZone:
    """Trust zone configuration"""
    name: str
    ip_range: str
    trust_level: str
    dhcp_pool_start: Optional[str]
    dhcp_pool_end: Optional[str]
    dhcp_enabled: bool = True


class TrustManager:
    """
    Zero Trust device enrollment and zone management.

    Handles:
    - Device enrollment workflow
    - Zone assignment and reassignment
    - Trust state persistence
    - Audit logging
    """

    def __init__(self, config: dict, db_path: str, gateway=None):
        """
        Initialize trust manager.

        Args:
            config: RAKSHAK configuration dictionary
            db_path: Path to SQLite database
            gateway: RakshakGateway instance for firewall control
        """
        self.config = config
        self.db_path = db_path
        self.gateway = gateway

        # Parse zone configuration
        zt_config = config.get("zero_trust", {})
        self.zones: Dict[str, TrustZone] = {}
        self.default_zone = zt_config.get("default_zone", "guest")

        for zone_name, zone_config in zt_config.get("zones", {}).items():
            self.zones[zone_name] = TrustZone(
                name=zone_name,
                ip_range=zone_config.get("ip_range", ""),
                trust_level=zone_config.get("trust_level", "untrusted"),
                dhcp_pool_start=zone_config.get("dhcp_pool_start"),
                dhcp_pool_end=zone_config.get("dhcp_pool_end"),
                dhcp_enabled=zone_config.get("dhcp_enabled", True)
            )

        logger.info(f"TrustManager initialized with {len(self.zones)} zones")
        logger.info(f"Default zone: {self.default_zone}")

    def assign_to_default_zone(self, device: dict) -> dict:
        """
        Assign unknown device to default (guest) zone.

        Args:
            device: Device dictionary with ip, mac, hostname

        Returns:
            Updated device dictionary with zone assignment
        """
        device_ip = device.get("ip")
        device_mac = device.get("mac")
        device_hostname = device.get("hostname", "unknown")

        logger.info(f"Assigning unknown device {device_ip} ({device_mac}) to {self.default_zone} zone")

        # Get guest zone IP from pool
        guest_zone = self.zones.get(self.default_zone)
        if not guest_zone:
            logger.error(f"Default zone '{self.default_zone}' not found in configuration")
            return device

        # Update device record in database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE devices
                SET enrollment_status = 'pending',
                    zone = ?
                WHERE ip = ? OR mac = ?
            """, (self.default_zone, device_ip, device_mac))

            conn.commit()
            conn.close()

            # Log enrollment event
            self._log_enrollment_event(
                device_mac=device_mac,
                action="auto_assign_guest",
                old_status="new",
                new_status="pending",
                zone_assigned=self.default_zone,
                performed_by="system"
            )

            device["enrollment_status"] = "pending"
            device["zone"] = self.default_zone

            logger.info(f"Device {device_ip} assigned to {self.default_zone} zone")

        except Exception as e:
            logger.error(f"Failed to assign device to default zone: {e}")

        return device

    def initiate_enrollment(self, device_ip: str, device_mac: Optional[str] = None) -> bool:
        """
        Mark device as pending enrollment.

        Args:
            device_ip: Device IP address
            device_mac: Device MAC address (optional)

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Initiating enrollment for device {device_ip}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE devices
                SET enrollment_status = 'pending'
                WHERE ip = ? OR mac = ?
            """, (device_ip, device_mac))

            conn.commit()
            conn.close()

            # Log enrollment event
            if device_mac:
                self._log_enrollment_event(
                    device_mac=device_mac,
                    action="initiate_enrollment",
                    old_status="unknown",
                    new_status="pending",
                    zone_assigned=None,
                    performed_by="admin"
                )

            logger.info(f"Device {device_ip} marked as pending enrollment")
            return True

        except Exception as e:
            logger.error(f"Failed to initiate enrollment: {e}")
            return False

    def approve_enrollment(self, device_ip: str, zone: str, approved_by: str) -> bool:
        """
        Approve device enrollment and assign to zone.

        Args:
            device_ip: Device IP address
            zone: Target zone (mgmt, main, iot, guest)
            approved_by: Username of approver

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Approving enrollment for {device_ip} to {zone} zone by {approved_by}")

        # Validate zone
        if zone not in self.zones:
            logger.error(f"Invalid zone: {zone}")
            return False

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get device MAC
            cursor.execute("SELECT mac, zone FROM devices WHERE ip = ?", (device_ip,))
            result = cursor.fetchone()

            if not result:
                logger.error(f"Device {device_ip} not found in database")
                conn.close()
                return False

            device_mac, old_zone = result

            # Get new IP from zone pool (for DHCP reassignment)
            # In production, this would integrate with DHCP server
            # For now, just update the zone field

            # Update device record
            cursor.execute("""
                UPDATE devices
                SET enrollment_status = 'enrolled',
                    zone = ?,
                    enrollment_date = ?,
                    enrolled_by = ?
                WHERE ip = ?
            """, (zone, datetime.now().isoformat(), approved_by, device_ip))

            conn.commit()
            conn.close()

            # Log enrollment event
            self._log_enrollment_event(
                device_mac=device_mac,
                action="approve_enrollment",
                old_status="pending",
                new_status="enrolled",
                zone_assigned=zone,
                performed_by=approved_by
            )

            # Log zone change
            if old_zone != zone:
                self._log_zone_change(
                    device_mac=device_mac,
                    old_zone=old_zone,
                    new_zone=zone,
                    changed_by=approved_by,
                    reason="enrollment_approval"
                )

            # Apply firewall rules for zone
            if self.gateway:
                self._apply_zone_firewall_rules(device_ip, zone)

            logger.info(f"Device {device_ip} enrolled to {zone} zone")
            return True

        except Exception as e:
            logger.error(f"Failed to approve enrollment: {e}")
            return False

    def get_zone_for_ip(self, ip: str) -> Optional[str]:
        """
        Determine which zone an IP belongs to.

        Args:
            ip: IP address to check

        Returns:
            Zone name or None if not found
        """
        try:
            ip_obj = ipaddress.ip_address(ip)

            for zone_name, zone in self.zones.items():
                # Parse IP range
                if "-" in zone.ip_range:
                    start_ip, end_ip = zone.ip_range.split("-")
                    start_obj = ipaddress.ip_address(start_ip.strip())
                    end_obj = ipaddress.ip_address(end_ip.strip())

                    if start_obj <= ip_obj <= end_obj:
                        return zone_name
                elif "/" in zone.ip_range:
                    # CIDR notation
                    network = ipaddress.ip_network(zone.ip_range, strict=False)
                    if ip_obj in network:
                        return zone_name

            return None

        except Exception as e:
            logger.error(f"Failed to determine zone for IP {ip}: {e}")
            return None

    def get_pending_devices(self) -> List[dict]:
        """
        Get all devices awaiting enrollment approval.

        Returns:
            List of device dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT ip, mac, hostname, zone, enrollment_status, first_seen
                FROM devices
                WHERE enrollment_status IN ('pending', 'unknown')
                ORDER BY first_seen DESC
            """)

            devices = []
            for row in cursor.fetchall():
                devices.append({
                    "ip": row[0],
                    "mac": row[1],
                    "hostname": row[2],
                    "zone": row[3],
                    "enrollment_status": row[4],
                    "first_seen": row[5]
                })

            conn.close()
            return devices

        except Exception as e:
            logger.error(f"Failed to get pending devices: {e}")
            return []

    def get_enrollment_status(self, device_ip: str) -> Optional[str]:
        """
        Get enrollment status for a device.

        Args:
            device_ip: Device IP address

        Returns:
            Enrollment status or None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT enrollment_status FROM devices WHERE ip = ?
            """, (device_ip,))

            result = cursor.fetchone()
            conn.close()

            return result[0] if result else None

        except Exception as e:
            logger.error(f"Failed to get enrollment status: {e}")
            return None

    def _log_enrollment_event(self, device_mac: str, action: str,
                               old_status: str, new_status: str,
                               zone_assigned: Optional[str], performed_by: str):
        """Log enrollment event to audit log."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO enrollment_log
                (device_mac, action, old_status, new_status, zone_assigned,
                 performed_by, performed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (device_mac, action, old_status, new_status, zone_assigned,
                  performed_by, datetime.now().isoformat()))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Failed to log enrollment event: {e}")

    def _log_zone_change(self, device_mac: str, old_zone: Optional[str],
                         new_zone: str, changed_by: str, reason: str):
        """Log zone change to history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO zone_history
                (device_mac, old_zone, new_zone, changed_at, changed_by, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (device_mac, old_zone, new_zone, datetime.now().isoformat(),
                  changed_by, reason))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Failed to log zone change: {e}")

    def _apply_zone_firewall_rules(self, device_ip: str, zone: str):
        """Apply firewall rules for device zone assignment."""
        if not self.gateway:
            logger.warning("No gateway instance available for firewall rule application")
            return

        logger.info(f"Applying {zone} zone firewall rules for {device_ip}")

        # Zone-specific firewall rules are handled by gateway's zone chains
        # This is just a placeholder for future integration
        # The actual enforcement happens in gateway.py via RAKSHAK_ZONE_* chains
        pass

    def get_zone_statistics(self) -> Dict[str, int]:
        """
        Get device count per zone.

        Returns:
            Dictionary with zone names as keys and device counts as values
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT zone, COUNT(*) as count
                FROM devices
                GROUP BY zone
            """)

            stats = {}
            for row in cursor.fetchall():
                zone_name = row[0] or "unassigned"
                count = row[1]
                stats[zone_name] = count

            # Ensure all zones are represented
            for zone_name in self.zones.keys():
                if zone_name not in stats:
                    stats[zone_name] = 0

            conn.close()
            return stats

        except Exception as e:
            logger.error(f"Failed to get zone statistics: {e}")
            return {}
