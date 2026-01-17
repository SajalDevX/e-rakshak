#!/usr/bin/env python3
"""
DNS-Based Whitelist Manager
============================

Implements application-layer security through DNS snooping and dynamic
IP whitelisting using ipsets.

Key Features:
- Monitor DNS queries from devices
- Match queries against vendor-specific domain patterns
- Dynamically add resolved IPs to per-device ipsets
- Automatic expiration of stale entries
- Integration with iptables for enforcement

Example:
    Camera queries wyze-api.wyzecam.com → 52.32.12.45
    → Add 52.32.12.45 to camera_001_allowed_dst ipset (1hr timeout)
    → Traffic to 52.32.12.45:443 now allowed by iptables

Author: Team RAKSHAK
"""

import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
import fnmatch
import json

from loguru import logger


@dataclass
class DNSQuery:
    """DNS query record."""
    device_ip: str
    device_mac: str
    domain: str
    resolved_ip: str
    timestamp: datetime
    vendor: Optional[str] = None
    allowed: bool = False


class DNSWhitelistManager:
    """
    Manages DNS-based application whitelisting for IoT devices.

    Features:
    - DNS query monitoring
    - Vendor domain pattern matching
    - Dynamic ipset management
    - Per-device IP whitelists
    - Automatic cleanup of stale entries
    """

    def __init__(self, config: dict, threat_logger=None):
        """
        Initialize DNS whitelist manager.

        Args:
            config: Configuration dictionary
            threat_logger: ThreatLogger instance for logging queries
        """
        self.config = config
        self.threat_logger = threat_logger

        # Configuration
        dns_config = config.get("zero_trust", {}).get("dns_whitelist", {})
        self.enabled = dns_config.get("enabled", True)
        self.default_ttl = dns_config.get("default_ttl", 3600)  # 1 hour
        self.cleanup_interval = dns_config.get("cleanup_interval", 300)  # 5 minutes

        # Device-specific domain whitelists
        # Format: device_type → [domain_patterns]
        self.device_domain_whitelist = dns_config.get("device_whitelist", {
            "camera": [
                r".*\.wyze\.com$",
                r".*\.wyzecam\.com$",
                r".*\.nest\.com$",
                r".*\.ring\.com$",
                r".*\.hik-connect\.com$",
                r".*\.arlo\.com$"
            ],
            "smart_speaker": [
                r".*\.amazon\.com$",
                r".*\.googleapis\.com$",
                r".*\.google\.com$",
                r".*\.alexa\.com$"
            ],
            "smart_plug": [
                r".*\.tplinkcloud\.com$",
                r".*\.tuya\.com$",
                r".*\.kasaapi\.com$"
            ],
            "smart_bulb": [
                r".*\.meethue\.com$",
                r".*\.philips-hue\.com$"
            ]
        })

        # Active ipsets per device
        # Format: device_id → ipset_name
        self.device_ipsets: Dict[str, str] = {}

        # DNS query cache
        # Format: (device_ip, domain) → DNSQuery
        self.query_cache: Dict[tuple, DNSQuery] = {}

        # Locks for thread safety
        self._lock = threading.Lock()
        self._cache_lock = threading.Lock()

        # Cleanup thread
        self._running = False
        self._cleanup_thread = None

        # Statistics
        self.stats = {
            "total_queries": 0,
            "allowed_queries": 0,
            "blocked_queries": 0,
            "ipsets_created": 0,
            "ips_added": 0
        }

        logger.info(f"DNSWhitelistManager initialized (enabled={self.enabled})")

    def start(self):
        """Start DNS whitelist manager."""
        if not self.enabled:
            logger.warning("DNSWhitelistManager is disabled in config")
            return

        if self._running:
            logger.warning("DNSWhitelistManager already running")
            return

        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="DNSCleanup"
        )
        self._cleanup_thread.start()
        logger.info("DNSWhitelistManager started")

    def stop(self):
        """Stop DNS whitelist manager."""
        if not self._running:
            return

        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
        logger.info("DNSWhitelistManager stopped")

    def process_dns_query(
        self,
        device_ip: str,
        device_mac: str,
        device_type: str,
        domain: str,
        resolved_ip: str
    ) -> bool:
        """
        Process a DNS query and update whitelist if allowed.

        Args:
            device_ip: Source device IP
            device_mac: Source device MAC
            device_type: Device type (camera, smart_plug, etc.)
            domain: Queried domain name
            resolved_ip: Resolved IP address

        Returns:
            True if query allowed, False if blocked
        """
        with self._lock:
            self.stats["total_queries"] += 1

        # Check if domain is allowed for this device type
        allowed, vendor = self._is_domain_allowed(device_type, domain)

        # Create DNS query record
        query = DNSQuery(
            device_ip=device_ip,
            device_mac=device_mac,
            domain=domain,
            resolved_ip=resolved_ip,
            timestamp=datetime.now(),
            vendor=vendor,
            allowed=allowed
        )

        # Cache query
        with self._cache_lock:
            self.query_cache[(device_ip, domain)] = query

        # Log to database
        if self.threat_logger:
            self.threat_logger.log_cloud_endpoint(
                device_ip=device_ip,
                device_mac=device_mac,
                domain=domain,
                resolved_ip=resolved_ip,
                vendor=vendor
            )

        if allowed:
            # Add resolved IP to device's whitelist
            self._add_to_device_whitelist(
                device_ip=device_ip,
                device_mac=device_mac,
                resolved_ip=resolved_ip,
                domain=domain
            )

            with self._lock:
                self.stats["allowed_queries"] += 1

            logger.debug(
                f"DNS allowed: {device_ip} → {domain} ({resolved_ip}) [{vendor}]"
            )
            return True
        else:
            with self._lock:
                self.stats["blocked_queries"] += 1

            logger.warning(
                f"DNS blocked: {device_ip} → {domain} ({resolved_ip}) "
                f"[type={device_type}, not in whitelist]"
            )
            return False

    def _is_domain_allowed(self, device_type: str, domain: str) -> tuple:
        """
        Check if domain is allowed for device type.

        Args:
            device_type: Device type
            domain: Domain name

        Returns:
            Tuple of (allowed: bool, vendor: Optional[str])
        """
        device_type_lower = device_type.lower() if device_type else "unknown"

        # Get domain patterns for device type
        patterns = self.device_domain_whitelist.get(device_type_lower, [])

        # Check if domain matches any pattern
        for pattern in patterns:
            if fnmatch.fnmatch(domain.lower(), pattern.lower()):
                # Extract vendor from domain
                vendor = self._extract_vendor_from_domain(domain)
                return (True, vendor)

        # Not in whitelist
        return (False, None)

    def _extract_vendor_from_domain(self, domain: str) -> Optional[str]:
        """Extract vendor name from domain."""
        domain_lower = domain.lower()

        vendor_keywords = {
            "wyze": "Wyze Labs",
            "nest": "Google Nest",
            "ring": "Ring",
            "hik-connect": "Hikvision",
            "arlo": "Arlo",
            "amazon": "Amazon",
            "google": "Google",
            "alexa": "Amazon",
            "tplink": "TP-Link",
            "tuya": "Tuya",
            "kasa": "TP-Link",
            "meethue": "Philips",
            "philips": "Philips"
        }

        for keyword, vendor in vendor_keywords.items():
            if keyword in domain_lower:
                return vendor

        return None

    def _add_to_device_whitelist(
        self,
        device_ip: str,
        device_mac: str,
        resolved_ip: str,
        domain: str
    ):
        """
        Add resolved IP to device's ipset whitelist.

        Args:
            device_ip: Device IP address
            device_mac: Device MAC address
            resolved_ip: Resolved IP to whitelist
            domain: Domain that was resolved
        """
        # Generate device ID from MAC
        device_id = device_mac.replace(":", "").lower()[:12]
        ipset_name = f"rakshak_allowed_{device_id}"

        # Create ipset if doesn't exist
        if ipset_name not in self.device_ipsets:
            if self._create_ipset(ipset_name):
                self.device_ipsets[ipset_name] = device_id
                with self._lock:
                    self.stats["ipsets_created"] += 1

        # Add IP to ipset with timeout
        if self._add_ip_to_ipset(ipset_name, resolved_ip, timeout=self.default_ttl):
            with self._lock:
                self.stats["ips_added"] += 1

            logger.debug(f"Added {resolved_ip} to {ipset_name} (domain: {domain})")

    def _create_ipset(self, ipset_name: str) -> bool:
        """
        Create an ipset for device whitelist.

        Args:
            ipset_name: Name of ipset to create

        Returns:
            True if created successfully
        """
        try:
            # Check if ipset already exists
            result = subprocess.run(
                ["ipset", "list", ipset_name],
                capture_output=True,
                timeout=5
            )

            if result.returncode == 0:
                logger.debug(f"ipset {ipset_name} already exists")
                return True

            # Create new ipset with timeout support
            subprocess.run(
                [
                    "ipset", "create", ipset_name,
                    "hash:ip", "timeout", str(self.default_ttl)
                ],
                capture_output=True,
                check=True,
                timeout=5
            )

            logger.info(f"Created ipset: {ipset_name}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create ipset {ipset_name}: {e.stderr.decode()}")
            return False
        except Exception as e:
            logger.error(f"Error creating ipset {ipset_name}: {e}")
            return False

    def _add_ip_to_ipset(self, ipset_name: str, ip: str, timeout: int = None) -> bool:
        """
        Add IP to ipset with optional timeout.

        Args:
            ipset_name: Name of ipset
            ip: IP address to add
            timeout: Timeout in seconds (None = permanent)

        Returns:
            True if added successfully
        """
        try:
            cmd = ["ipset", "add", ipset_name, ip, "-exist"]
            if timeout:
                cmd.extend(["timeout", str(timeout)])

            subprocess.run(
                cmd,
                capture_output=True,
                check=True,
                timeout=5
            )

            return True

        except subprocess.CalledProcessError as e:
            # Ignore "already exists" errors
            if b"already added" not in e.stderr:
                logger.error(f"Failed to add {ip} to {ipset_name}: {e.stderr.decode()}")
            return False
        except Exception as e:
            logger.error(f"Error adding {ip} to {ipset_name}: {e}")
            return False

    def get_device_whitelist(self, device_mac: str) -> List[str]:
        """
        Get whitelisted IPs for a device.

        Args:
            device_mac: Device MAC address

        Returns:
            List of whitelisted IP addresses
        """
        device_id = device_mac.replace(":", "").lower()[:12]
        ipset_name = f"rakshak_allowed_{device_id}"

        try:
            result = subprocess.run(
                ["ipset", "list", ipset_name],
                capture_output=True,
                timeout=5
            )

            if result.returncode != 0:
                return []

            # Parse ipset output
            output = result.stdout.decode()
            ips = []
            in_members = False

            for line in output.split("\n"):
                if line.startswith("Members:"):
                    in_members = True
                    continue
                if in_members and line.strip():
                    # Extract IP (may have timeout suffix)
                    ip = line.split()[0]
                    ips.append(ip)

            return ips

        except Exception as e:
            logger.error(f"Error getting whitelist for {device_mac}: {e}")
            return []

    def clear_device_whitelist(self, device_mac: str):
        """
        Clear all whitelisted IPs for a device.

        Args:
            device_mac: Device MAC address
        """
        device_id = device_mac.replace(":", "").lower()[:12]
        ipset_name = f"rakshak_allowed_{device_id}"

        try:
            subprocess.run(
                ["ipset", "flush", ipset_name],
                capture_output=True,
                timeout=5
            )
            logger.info(f"Cleared whitelist for {device_mac}")

        except Exception as e:
            logger.error(f"Error clearing whitelist for {device_mac}: {e}")

    def _cleanup_loop(self):
        """Background loop for cleaning up stale entries."""
        logger.info("DNS whitelist cleanup loop started")

        while self._running:
            try:
                # Clean up old query cache entries
                with self._cache_lock:
                    cutoff_time = datetime.now() - timedelta(hours=24)
                    old_keys = [
                        key for key, query in self.query_cache.items()
                        if query.timestamp < cutoff_time
                    ]
                    for key in old_keys:
                        del self.query_cache[key]

                    if old_keys:
                        logger.debug(f"Cleaned up {len(old_keys)} old DNS query cache entries")

                # Sleep until next cleanup
                time.sleep(self.cleanup_interval)

            except Exception as e:
                logger.error(f"Error in DNS cleanup loop: {e}")
                time.sleep(60)

    def get_statistics(self) -> dict:
        """Get DNS whitelist statistics."""
        with self._lock:
            return self.stats.copy()

    def get_query_history(self, device_ip: str, limit: int = 100) -> List[DNSQuery]:
        """
        Get DNS query history for a device.

        Args:
            device_ip: Device IP address
            limit: Maximum number of queries to return

        Returns:
            List of DNSQuery objects
        """
        with self._cache_lock:
            queries = [
                query for (ip, _), query in self.query_cache.items()
                if ip == device_ip
            ]
            # Sort by timestamp descending
            queries.sort(key=lambda q: q.timestamp, reverse=True)
            return queries[:limit]
