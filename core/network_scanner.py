#!/usr/bin/env python3
"""
RAKSHAK Network Scanner - MAYA
==============================

Morphing Adaptive Yielding Architecture

Features:
- ARP-based device discovery
- Nmap service fingerprinting
- Risk score calculation
- Device morphing for honeypot creation
- Simulation mode support

Author: Team RAKSHAK
"""

import os
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field

from loguru import logger

# Conditional imports for network scanning
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - real network scanning disabled")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("python-nmap not available - service fingerprinting disabled")

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    logger.warning("netifaces not available - auto-detection disabled")


@dataclass
class Device:
    """Represents a discovered network device."""
    id: str
    ip: str
    mac: str
    hostname: str = ""
    device_type: str = "unknown"
    manufacturer: str = "unknown"
    os: str = "unknown"
    os_version: str = ""
    firmware: str = ""
    services: List[Dict] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    status: str = "active"  # active, isolated, honeypot
    is_honeypot: bool = False
    zone: str = "unknown"  # Zero Trust zone (guest, iot, main, mgmt, quarantine)
    enrollment_status: str = "unknown"  # unknown, pending, enrolled

    def to_dict(self) -> dict:
        return asdict(self)


class NetworkScanner:
    """
    MAYA - Morphing Adaptive Yielding Architecture

    Responsible for:
    - Discovering devices on the network
    - Fingerprinting devices (OS, services)
    - Calculating risk scores
    - Providing device profiles for honeypot cloning
    """

    # Known risky services and their base risk scores
    RISKY_SERVICES = {
        "telnet": 30,       # Unencrypted, easily exploitable
        "ftp": 25,          # Unencrypted file transfer
        "http": 15,         # Unencrypted web
        "upnp": 20,         # Often misconfigured
        "mqtt": 25,         # IoT protocol, often unsecured
        "rtsp": 20,         # Video streaming, privacy risk
        "ssh": 10,          # If on default port
        "smb": 25,          # Windows file sharing
        "vnc": 30,          # Remote desktop
        "rdp": 25,          # Windows remote desktop
    }

    # MAC OUI prefixes for device identification
    MAC_PREFIXES = {
        "00:17:88": ("Philips", "smart_bulb"),
        "B4:E6:2D": ("TP-Link", "router"),
        "44:07:0B": ("Google", "smart_speaker"),
        "F0:27:2D": ("Amazon", "alexa"),
        "50:C7:BF": ("TP-Link", "smart_plug"),
        "D8:6C:63": ("Samsung", "smart_tv"),
        "2C:AA:8E": ("Wyze", "camera"),
        "18:B4:30": ("Nest", "thermostat"),
        "AC:CC:8E": ("Roku", "streaming"),
    }

    def __init__(self, config: dict, threat_logger=None, gateway=None, trust_manager=None):
        """
        Initialize the network scanner.

        Args:
            config: Configuration dictionary
            threat_logger: ThreatLogger instance
            gateway: RakshakGateway instance (for DHCP-based discovery in gateway mode)
            trust_manager: TrustManager instance (for Zero Trust zone assignment)
        """
        self.config = config
        self.threat_logger = threat_logger
        self.gateway = gateway  # Gateway reference for DHCP-based discovery
        self.trust_manager = trust_manager  # Trust Manager for zone assignment
        self.network_config = config.get("network", {})
        self.simulation_config = config.get("simulation", {})

        # Device storage
        self.devices: Dict[str, Device] = {}
        self._devices_lock = threading.Lock()
        self._mac_to_ip: Dict[str, str] = {}  # MAC→IP index for detecting IP changes

        # Startup grace period for preventing false inactive status
        self._startup_time = datetime.now()
        self._startup_grace_period = 120  # 2 minutes grace period

        # Simulation mode
        self.simulation_mode = self.simulation_config.get("enabled", True)

        # Network interface (auto-detect if "auto" or not specified)
        configured_interface = self.network_config.get("interface", "auto")
        if configured_interface == "auto":
            self.interface = self._detect_network_interface()
        else:
            self.interface = configured_interface

        # Network range (auto-detect if "auto" or not specified)
        configured_network = self.network_config.get("scan_network", "auto")
        if configured_network == "auto":
            self.scan_network = self._detect_network_range()
        else:
            self.scan_network = configured_network

        self.whitelist_ips = set(self.network_config.get("whitelist_ips", []))

        # Nmap scanner
        self.nm = None
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                logger.warning(f"nmap binary not found: {e}")
                self.nm = None

        # Device ID counter
        self._device_counter = 0

        # Passive discovery for static IP devices (cameras, NVRs)
        self.passive_discovery = None
        self._init_passive_discovery()

        # Load simulated devices if in simulation mode
        if self.simulation_mode:
            self._load_simulated_devices()
        else:
            # In gateway mode, load devices from database
            self._load_devices_from_db()

        logger.info(f"NetworkScanner initialized (simulation={self.simulation_mode}, interface={self.interface})")

    def _generate_device_id(self) -> str:
        """Generate unique device ID."""
        self._device_counter += 1
        return f"DEV-{self._device_counter:04d}"

    def _detect_network_interface(self) -> str:
        """Auto-detect the best network interface."""
        # If gateway is available and bridge mode is enabled, use bridge interface
        if self.gateway:
            # Check for bridge mode - use bridge name if enabled
            if hasattr(self.gateway, 'config') and self.gateway.config.bridge_mode:
                bridge_name = self.gateway.config.bridge_name
                logger.info(f"MAYA: Using bridge interface: {bridge_name} (bridge mode enabled)")
                return bridge_name

            # Fall back to gateway LAN interface (which may already be the bridge)
            if hasattr(self.gateway, 'config') and self.gateway.config.lan_interface:
                lan_if = self.gateway.config.lan_interface
                logger.info(f"MAYA: Using gateway LAN interface: {lan_if}")
                return lan_if

        if not NETIFACES_AVAILABLE:
            logger.warning("netifaces not available, using default eth0")
            return self.network_config.get("interface", "eth0")

        try:
            interfaces = netifaces.interfaces()

            # Exclude virtual/docker interfaces
            excluded_prefixes = ['br-', 'docker', 'veth', 'virbr', 'lo']

            # Priority order for interface names (USB ethernet first for our setup)
            priority_prefixes = ['enx', 'eth', 'enp', 'ens', 'eno', 'em', 'wlan', 'wlp', 'wlo']

            for prefix in priority_prefixes:
                for iface in interfaces:
                    # Skip excluded interfaces
                    if any(iface.startswith(excl) for excl in excluded_prefixes):
                        continue
                    if iface.startswith(prefix):
                        # Check if interface has IPv4 address
                        addrs = netifaces.ifaddresses(iface)
                        if netifaces.AF_INET in addrs:
                            ipv4 = addrs[netifaces.AF_INET][0]
                            if 'addr' in ipv4 and not ipv4['addr'].startswith('127.'):
                                logger.info(f"Auto-detected network interface: {iface}")
                                return iface

            # Fallback: find any interface with IPv4 (except loopback and virtual)
            for iface in interfaces:
                # Skip excluded interfaces
                if any(iface.startswith(excl) for excl in excluded_prefixes):
                    continue
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    logger.info(f"Using fallback interface: {iface}")
                    return iface

        except Exception as e:
            logger.error(f"Failed to auto-detect interface: {e}")

        return "eth0"

    def _detect_network_range(self) -> str:
        """Auto-detect the network range from interface."""
        if not NETIFACES_AVAILABLE:
            logger.warning("netifaces not available, using default 192.168.1.0/24")
            return "192.168.1.0/24"

        try:
            addrs = netifaces.ifaddresses(self.interface)

            if netifaces.AF_INET in addrs:
                ipv4 = addrs[netifaces.AF_INET][0]
                ip = ipv4.get('addr', '')
                netmask = ipv4.get('netmask', '255.255.255.0')

                # Calculate network range using ipaddress module
                from ipaddress import IPv4Network
                network = IPv4Network(f"{ip}/{netmask}", strict=False)
                network_range = str(network)
                logger.info(f"Auto-detected network range: {network_range}")
                return network_range

        except Exception as e:
            logger.error(f"Failed to auto-detect network range: {e}")

        return "192.168.1.0/24"

    def _init_passive_discovery(self):
        """Initialize passive discovery for static IP devices."""
        # Skip in simulation mode
        if self.simulation_mode:
            return

        # Check if passive discovery is enabled in config
        passive_config = self.network_config.get("passive_discovery", {})
        if not passive_config.get("enabled", True):
            logger.info("MAYA: Passive discovery disabled in config")
            return

        # Only enable in gateway/bridge mode for full visibility
        if not self.gateway:
            logger.info("MAYA: Passive discovery requires gateway mode")
            return

        try:
            from core.passive_discovery import PassiveDiscovery

            self.passive_discovery = PassiveDiscovery(
                interface=self.interface,
                ssdp_enabled=passive_config.get("ssdp_enabled", True),
                onvif_enabled=passive_config.get("onvif_enabled", True),
                rtsp_probe_enabled=passive_config.get("rtsp_probe_enabled", True),
                arp_listener_enabled=passive_config.get("arp_listener_enabled", True),
                on_device_discovered=self._on_passive_device_found
            )
            logger.info(f"MAYA: Passive discovery initialized on {self.interface}")

        except ImportError:
            logger.warning("MAYA: Passive discovery module not available")
        except Exception as e:
            logger.error(f"MAYA: Failed to initialize passive discovery: {e}")

    def start_passive_discovery(self):
        """Start passive discovery listeners."""
        if self.passive_discovery:
            self.passive_discovery.start()
            logger.info("MAYA: Passive discovery started")

    def stop_passive_discovery(self):
        """Stop passive discovery listeners."""
        if self.passive_discovery:
            self.passive_discovery.stop()
            logger.info("MAYA: Passive discovery stopped")

    def _on_passive_device_found(self, device_info: dict):
        """
        Callback when passive discovery finds a device.

        Merges passively discovered devices (static IPs) with DHCP-tracked devices.
        """
        ip = device_info.get("ip")
        if not ip:
            return

        # Skip if already known from DHCP
        with self._devices_lock:
            if ip in self.devices:
                # Update existing device with additional info from passive discovery
                device = self.devices[ip]

                # ACTIVE STATUS FIX: Passive discovery confirms device is active
                if device.status == "inactive":
                    device.status = "active"
                    logger.info(f"MAYA: Device {ip} is now active (detected via {device_info.get('method', 'passive')})")

                if device_info.get("mac") and device.mac == "unknown":
                    device.mac = device_info["mac"]
                if device_info.get("device_type") and device.device_type == "unknown":
                    device.device_type = device_info["device_type"]
                if device_info.get("manufacturer") and device.manufacturer == "unknown":
                    device.manufacturer = device_info["manufacturer"]
                # Add discovered services
                for svc in device_info.get("services", []):
                    if svc not in device.services:
                        device.services.append(svc)
                for port in device_info.get("open_ports", []):
                    if port not in device.open_ports:
                        device.open_ports.append(port)
                device.last_seen = datetime.now().isoformat()
                logger.debug(f"MAYA: Updated device {ip} with passive discovery info")

                # Update device in database
                self._save_device_to_db(device)
                return

            # New device - create entry for static IP device
            device = Device(
                id=self._generate_device_id(),
                ip=ip,
                mac=device_info.get("mac", "unknown"),
                hostname=device_info.get("hostname", ""),
                device_type=device_info.get("device_type", "unknown"),
                manufacturer=device_info.get("manufacturer", "unknown"),
                services=device_info.get("services", []),
                open_ports=device_info.get("open_ports", []),
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                status="active"
            )

            # Calculate risk score
            device.risk_score = self._calculate_risk_score(device)

            self.devices[ip] = device
            if device.mac and device.mac != "unknown":
                self._mac_to_ip[device.mac] = ip

            logger.info(f"MAYA: Discovered static IP device: {ip} ({device.device_type}, {device.manufacturer})")

            # Save new device to database with zone assignment
            self._save_device_to_db(device)

    def _save_device_to_db(self, device: Device):
        """
        Save or update device in database with Zero Trust zone assignment.

        Args:
            device: Device object to save
        """
        if not self.threat_logger:
            return

        # First, check if device already exists in database with enrolled status
        existing_zone = None
        existing_status = None

        try:
            import sqlite3
            conn = sqlite3.connect(self.threat_logger.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT zone, enrollment_status FROM devices WHERE ip = ? OR mac = ?",
                (device.ip, device.mac)
            )
            result = cursor.fetchone()
            conn.close()

            if result:
                existing_zone, existing_status = result
        except Exception as e:
            logger.debug(f"Could not check existing device status: {e}")

        # Determine zone assignment
        zone = "guest"  # Default zone for unknown devices
        enrollment_status = "unknown"

        # CRITICAL FIX: Preserve manually enrolled devices
        if existing_status == "enrolled" and existing_zone:
            # Device was manually enrolled - DO NOT override!
            zone = existing_zone
            enrollment_status = existing_status
            logger.debug(f"Preserving enrolled device {device.ip} in {zone} zone")
        else:
            # New device or not yet enrolled - calculate zone from IP
            if self.trust_manager:
                # Use TrustManager to determine zone from IP
                determined_zone = self.trust_manager.get_zone_for_ip(device.ip)
                if determined_zone:
                    zone = determined_zone
                    # ZERO TRUST FIX: All new devices start as 'unknown' regardless of zone
                    # Only manual approval via dashboard should set 'enrolled'
                    enrollment_status = "unknown"

        # Update Device object with zone info
        device.zone = zone
        device.enrollment_status = enrollment_status

        # Save to database using ThreatLogger
        self.threat_logger.log_device(
            ip=device.ip,
            mac=device.mac,
            hostname=device.hostname or "unknown",
            device_type=device.device_type or "unknown",
            os=device.os or "unknown",
            zone=zone,
            enrollment_status=enrollment_status,
            risk_score=device.risk_score
        )

        logger.debug(f"Saved device {device.ip} to database (zone={zone}, status={enrollment_status})")

    def get_passive_discovery_devices(self) -> Dict[str, dict]:
        """Get devices discovered via passive methods."""
        if self.passive_discovery:
            return self.passive_discovery.get_discovered_devices()
        return {}

    def _load_simulated_devices(self):
        """Load simulated devices from config."""
        fake_devices = self.simulation_config.get("fake_devices", [])

        for dev_config in fake_devices:
            device = Device(
                id=self._generate_device_id(),
                ip=dev_config.get("ip", "192.168.1.100"),
                mac=dev_config.get("mac", "AA:BB:CC:DD:EE:FF"),
                hostname=dev_config.get("name", "Unknown Device"),
                device_type=dev_config.get("device_type", "unknown"),
                risk_score=dev_config.get("risk_score", 50),
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                status="active"
            )

            # Add realistic details based on device type
            self._enrich_simulated_device(device)

            self.devices[device.ip] = device
            logger.debug(f"Loaded simulated device: {device.hostname} ({device.ip})")

        logger.info(f"Loaded {len(self.devices)} simulated devices")

    def _load_devices_from_db(self):
        """Load devices from database to populate in-memory cache."""
        if not self.threat_logger:
            return

        try:
            import sqlite3
            db_path = self.threat_logger.db_path
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT ip, mac, hostname, device_type, os,
                       zone, enrollment_status, risk_score,
                       first_seen, last_seen, status
                FROM devices
                WHERE status != 'inactive'
                ORDER BY last_seen DESC
            """)

            rows = cursor.fetchall()
            loaded_count = 0

            for row in rows:
                device = Device(
                    id=self._generate_device_id(),
                    ip=row['ip'],
                    mac=row['mac'] or "unknown",
                    hostname=row['hostname'] or "",
                    device_type=row['device_type'] or "unknown",
                    os=row['os'] or "unknown",
                    risk_score=row['risk_score'] or 0,
                    first_seen=row['first_seen'] or datetime.now().isoformat(),
                    last_seen=row['last_seen'] or datetime.now().isoformat(),
                    status=row['status'] or "active",
                    zone=row['zone'] or "unknown",
                    enrollment_status=row['enrollment_status'] or "unknown"
                )

                self.devices[device.ip] = device
                if device.mac and device.mac != "unknown":
                    self._mac_to_ip[device.mac] = device.ip

                loaded_count += 1

            conn.close()

            if loaded_count > 0:
                logger.info(f"Loaded {loaded_count} devices from database")
            else:
                logger.debug("No devices found in database")

        except Exception as e:
            logger.warning(f"Failed to load devices from database: {e}")

    def _enrich_simulated_device(self, device: Device):
        """Add realistic details to simulated device."""
        device_profiles = {
            "samsung_tv": {
                "manufacturer": "Samsung",
                "os": "Tizen 5.5",
                "services": [
                    {"name": "http", "port": 8080, "version": "Samsung TV Web"},
                    {"name": "upnp", "port": 1900, "version": "DLNA"}
                ],
                "open_ports": [8080, 1900, 8001, 8002],
                "risk_factors": ["UPnP enabled", "Web interface exposed"]
            },
            "wyze_cam": {
                "manufacturer": "Wyze Labs",
                "os": "Linux 3.4.35",
                "firmware": "4.9.8.1002",
                "services": [
                    {"name": "rtsp", "port": 554, "version": "RTSP 1.0"},
                    {"name": "http", "port": 80, "version": "lighttpd"}
                ],
                "open_ports": [80, 554, 8080],
                "risk_factors": ["RTSP exposed", "Default credentials common"]
            },
            "alexa": {
                "manufacturer": "Amazon",
                "os": "Fire OS 7.2",
                "services": [
                    {"name": "https", "port": 443, "version": "Amazon Device"}
                ],
                "open_ports": [443],
                "risk_factors": []
            },
            "tp_link": {
                "manufacturer": "TP-Link",
                "os": "Linux 2.6.36",
                "firmware": "3.15.3",
                "services": [
                    {"name": "http", "port": 80, "version": "TP-Link HTTP"},
                    {"name": "telnet", "port": 23, "version": "BusyBox"}
                ],
                "open_ports": [80, 23, 53],
                "risk_factors": ["Telnet enabled", "Admin interface exposed"]
            },
            "philips_hue": {
                "manufacturer": "Philips",
                "os": "Embedded Linux",
                "services": [
                    {"name": "http", "port": 80, "version": "Hue Bridge"}
                ],
                "open_ports": [80, 443],
                "risk_factors": []
            },
            "nest": {
                "manufacturer": "Google/Nest",
                "os": "Linux 4.4",
                "firmware": "5.9.3-7",
                "services": [
                    {"name": "https", "port": 443, "version": "Nest Device"}
                ],
                "open_ports": [443, 9543],
                "risk_factors": []
            },
            "august_lock": {
                "manufacturer": "August Home",
                "os": "Embedded",
                "services": [
                    {"name": "bluetooth", "port": 0, "version": "BLE 4.2"},
                    {"name": "https", "port": 443, "version": "August API"}
                ],
                "open_ports": [443],
                "risk_factors": ["Physical security device", "WiFi bridge"]
            },
            "playstation": {
                "manufacturer": "Sony",
                "os": "Orbis OS",
                "services": [
                    {"name": "http", "port": 80, "version": "PlayStation"},
                    {"name": "upnp", "port": 1900, "version": "DLNA"}
                ],
                "open_ports": [80, 1900, 9295, 9296],
                "risk_factors": ["UPnP enabled"]
            }
        }

        profile = device_profiles.get(device.device_type, {})
        device.manufacturer = profile.get("manufacturer", device.manufacturer)
        device.os = profile.get("os", device.os)
        device.firmware = profile.get("firmware", device.firmware)
        device.services = profile.get("services", [])
        device.open_ports = profile.get("open_ports", [])
        device.risk_factors = profile.get("risk_factors", [])

        # Recalculate risk score based on services
        if not device.risk_score:
            device.risk_score = self._calculate_risk_score(device)

    def discover_devices(self, network: str = None) -> List[Device]:
        """
        Discover devices on the network using ARP scan.

        Args:
            network: Network range to scan (e.g., "192.168.1.0/24")

        Returns:
            List of discovered Device objects
        """
        if self.simulation_mode:
            return self.get_simulated_devices()

        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available for network scanning")
            return []

        network = network or self.scan_network
        logger.info(f"Scanning network: {network}")

        try:
            # Suppress Scapy warnings
            conf.verb = 0

            # Create ARP request
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Send packet and receive responses
            timeout = self.network_config.get("arp_timeout", 3)
            result = srp(packet, timeout=timeout, verbose=0)[0]

            discovered = []
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc

                # Skip whitelisted IPs
                if ip in self.whitelist_ips:
                    continue

                # Check if device already exists
                if ip in self.devices:
                    device = self.devices[ip]
                    device.last_seen = datetime.now().isoformat()
                else:
                    device = Device(
                        id=self._generate_device_id(),
                        ip=ip,
                        mac=mac,
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat()
                    )
                    # Try to identify device
                    self._identify_device(device)

                discovered.append(device)

            logger.info(f"Discovered {len(discovered)} devices")
            return discovered

        except PermissionError:
            logger.error("Permission denied - network scanning requires root privileges")
            return []
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            return []

    def discover_devices_from_dhcp(self) -> List[Device]:
        """
        Discover devices from DHCP leases (gateway mode).

        This is more reliable than ARP scanning when RAKSHAK is the gateway,
        as we have authoritative information about all connected devices.

        Returns:
            List of Device objects from DHCP leases
        """
        if not self.gateway or not self.gateway.is_gateway_mode:
            logger.warning("DHCP discovery requires gateway mode")
            return self.discover_devices()  # Fall back to ARP scan

        devices = []
        leases = self.gateway.refresh_dhcp_leases()

        # Get current lease IPs to track disconnected devices
        current_lease_ips = {lease.ip_address for lease in leases.values()}

        # Calculate if we're still in startup grace period
        startup_grace_active = (datetime.now() - self._startup_time).total_seconds() < self._startup_grace_period

        with self._devices_lock:
            # Mark devices not in current leases as inactive
            for ip in list(self.devices.keys()):
                if ip not in current_lease_ips:
                    device = self.devices[ip]

                    # Check if device was recently seen (within 30 seconds)
                    recently_seen = False
                    try:
                        last_seen = datetime.fromisoformat(device.last_seen)
                        time_since_seen = (datetime.now() - last_seen).total_seconds()
                        recently_seen = time_since_seen < 30  # Give 30 seconds for DHCP lease
                    except (ValueError, TypeError):
                        pass

                    # GRACE PERIOD FIX: Don't mark inactive if:
                    # 1. During startup grace period, OR
                    # 2. Device was recently seen by passive discovery
                    if not startup_grace_active and not recently_seen and device.status == "active":
                        device.status = "inactive"
                        logger.info(f"Device {ip} marked as inactive (disconnected)")

            for mac, lease in leases.items():
                # Check if this MAC already has a device with different IP (IP changed)
                if mac in self._mac_to_ip:
                    old_ip = self._mac_to_ip[mac]
                    if old_ip != lease.ip_address and old_ip in self.devices:
                        # Device changed IP - update existing device instead of creating new
                        device = self.devices.pop(old_ip)  # Remove old IP entry
                        logger.info(f"MAYA: Device {mac} changed IP: {old_ip} → {lease.ip_address}")
                        device.ip = lease.ip_address
                        device.last_seen = datetime.now().isoformat()
                        device.hostname = lease.hostname if lease.hostname != "unknown" else device.hostname
                        device.status = "active" if lease.is_active else "inactive"
                        self.devices[lease.ip_address] = device
                        self._mac_to_ip[mac] = lease.ip_address
                        devices.append(device)
                        continue

                # Check if device already exists at this IP
                if lease.ip_address in self.devices:
                    device = self.devices[lease.ip_address]
                    device.last_seen = datetime.now().isoformat()
                    device.hostname = lease.hostname if lease.hostname != "unknown" else device.hostname
                    # Update status based on actual reachability (unless isolated)
                    if device.status != "isolated":
                        if lease.is_active and device.status == "inactive":
                            device.status = "active"
                            logger.info(f"Device {device.hostname} ({device.ip}) is now active")
                        elif not lease.is_active and device.status == "active":
                            device.status = "inactive"
                            logger.info(f"Device {device.hostname} ({device.ip}) is now inactive (disconnected)")
                else:
                    # Create new device from lease
                    device = Device(
                        id=self._generate_device_id(),
                        ip=lease.ip_address,
                        mac=lease.mac_address,
                        hostname=lease.hostname,
                        device_type=self._guess_device_type(lease.mac_address, lease.hostname),
                        first_seen=lease.lease_start.isoformat() if hasattr(lease.lease_start, 'isoformat') else str(lease.lease_start),
                        last_seen=datetime.now().isoformat(),
                        status="active" if lease.is_active else "inactive"
                    )

                    # Try to identify device from MAC
                    self._identify_device(device)

                    # Calculate risk score
                    device.risk_score = self._calculate_risk_score(device)

                # Check if device is isolated
                if lease.ip_address in self.gateway.isolated_devices:
                    device.status = "isolated"

                devices.append(device)

                # Update internal tracking
                self.devices[device.ip] = device
                # Track MAC→IP mapping
                if mac:
                    self._mac_to_ip[mac] = lease.ip_address

        logger.debug(f"Discovered {len(devices)} devices from DHCP leases")
        return devices

    def cleanup_stale_devices(self, inactive_threshold_seconds: int = 300) -> int:
        """
        Remove devices that have been inactive for longer than threshold.

        This prevents stale entries from accumulating when devices leave
        the network or change IP addresses.

        Args:
            inactive_threshold_seconds: Remove devices inactive for longer than this (default: 5 min)

        Returns:
            Number of devices removed
        """
        with self._devices_lock:
            now = datetime.now()
            to_remove = []

            for ip, device in self.devices.items():
                if device.status == "inactive":
                    try:
                        last_seen = datetime.fromisoformat(device.last_seen)
                        inactive_duration = (now - last_seen).total_seconds()
                        if inactive_duration > inactive_threshold_seconds:
                            to_remove.append(ip)
                    except (ValueError, TypeError):
                        # Invalid timestamp, mark for removal
                        to_remove.append(ip)

            for ip in to_remove:
                device = self.devices.pop(ip)
                # Also remove from MAC→IP index
                if device.mac and device.mac in self._mac_to_ip:
                    del self._mac_to_ip[device.mac]
                logger.info(f"MAYA: Removed stale device {ip} ({device.hostname or 'unknown'})")

            if to_remove:
                logger.info(f"MAYA: Cleaned up {len(to_remove)} stale device(s)")

            return len(to_remove)

    def _guess_device_type(self, mac: str, hostname: str) -> str:
        """Guess device type from MAC address and hostname."""
        # Check MAC OUI prefix
        if mac:
            mac_prefix = mac[:8].upper()
            if mac_prefix in self.MAC_PREFIXES:
                return self.MAC_PREFIXES[mac_prefix][1]

        # Check hostname hints
        hostname_lower = hostname.lower() if hostname else ""
        type_hints = {
            "camera": "camera",
            "cam": "camera",
            "wyze": "wyze_cam",
            "alexa": "alexa",
            "echo": "alexa",
            "tv": "samsung_tv",
            "samsung": "samsung_tv",
            "roku": "streaming",
            "fire": "streaming",
            "nest": "thermostat",
            "hue": "smart_bulb",
            "philips": "smart_bulb",
            "tp-link": "tp_link",
            "router": "router",
            "switch": "network_switch",
            "playstation": "playstation",
            "xbox": "gaming_console",
            "iphone": "mobile",
            "android": "mobile",
            "macbook": "laptop",
            "laptop": "laptop",
            "desktop": "desktop",
        }

        for hint, dev_type in type_hints.items():
            if hint in hostname_lower:
                return dev_type

        return "unknown"

    def _identify_device(self, device: Device):
        """Identify device type from MAC address and fingerprint."""
        # Check MAC OUI prefix
        mac_prefix = device.mac[:8].upper()
        if mac_prefix in self.MAC_PREFIXES:
            manufacturer, device_type = self.MAC_PREFIXES[mac_prefix]
            device.manufacturer = manufacturer
            device.device_type = device_type

        # Run nmap fingerprint if available
        if NMAP_AVAILABLE and self.nm:
            self._fingerprint_device(device)

    def _fingerprint_device(self, device: Device):
        """Run nmap scan to fingerprint device."""
        try:
            arguments = self.network_config.get("nmap_arguments", "-sV -O --osscan-guess")
            self.nm.scan(device.ip, arguments=arguments)

            if device.ip in self.nm.all_hosts():
                host = self.nm[device.ip]

                # Extract hostname
                device.hostname = host.hostname() or device.hostname

                # Extract OS info
                if "osmatch" in host and host["osmatch"]:
                    os_match = host["osmatch"][0]
                    device.os = os_match.get("name", device.os)

                # Extract services
                for proto in host.all_protocols():
                    for port in host[proto].keys():
                        service = host[proto][port]
                        device.services.append({
                            "name": service.get("name", "unknown"),
                            "port": port,
                            "version": service.get("version", ""),
                            "product": service.get("product", "")
                        })
                        device.open_ports.append(port)

                # Calculate risk score
                device.risk_score = self._calculate_risk_score(device)

        except Exception as e:
            logger.warning(f"Fingerprinting failed for {device.ip}: {e}")

    def _calculate_risk_score(self, device: Device) -> int:
        """
        Calculate risk score (0-100) based on device characteristics.

        Factors:
        - Open risky services
        - Known vulnerable devices
        - Outdated firmware
        - Default credentials likely
        """
        score = 0
        risk_factors = []

        # Check services
        for service in device.services:
            service_name = service.get("name", "").lower()
            if service_name in self.RISKY_SERVICES:
                score += self.RISKY_SERVICES[service_name]
                risk_factors.append(f"{service_name.upper()} service exposed")

        # High-risk device types
        high_risk_types = ["camera", "wyze_cam", "router", "tp_link"]
        if device.device_type in high_risk_types:
            score += 15
            risk_factors.append("High-risk device type")

        # Check for default ports
        default_dangerous_ports = [23, 21, 5900, 3389]  # telnet, ftp, vnc, rdp
        for port in device.open_ports:
            if port in default_dangerous_ports:
                score += 10
                risk_factors.append(f"Dangerous port {port} open")

        # Cap at 100
        score = min(score, 100)
        device.risk_factors = risk_factors

        return score

    def get_simulated_devices(self) -> List[Device]:
        """Get list of simulated devices."""
        with self._devices_lock:
            return list(self.devices.values())

    def get_device(self, ip: str) -> Optional[Device]:
        """Get device by IP address."""
        return self.devices.get(ip)

    def get_all_devices(self) -> List[Device]:
        """Get all known devices."""
        with self._devices_lock:
            return list(self.devices.values())

    def update_device(self, device: Device):
        """Update or add a device."""
        with self._devices_lock:
            device.last_seen = datetime.now().isoformat()
            self.devices[device.ip] = device

            # Save to database with zone assignment
            self._save_device_to_db(device)

    def isolate_device(self, device_ip: str) -> bool:
        """
        Isolate a device from the network.

        In gateway mode: Uses iptables rules (REAL isolation)
        In standalone mode: Just updates status (SIMULATED)

        Args:
            device_ip: IP address of device to isolate

        Returns:
            True if isolation successful
        """
        if device_ip not in self.devices:
            logger.warning(f"Device {device_ip} not found in device list")
            return False

        # Gateway mode: real isolation via iptables
        if self.gateway and self.gateway.is_gateway_mode:
            try:
                from core.gateway import IsolationLevel
                success = self.gateway.isolate_device(
                    ip_address=device_ip,
                    level=IsolationLevel.FULL,
                    reason="Isolated via NetworkScanner"
                )
                if success:
                    self.devices[device_ip].status = "isolated"
                    logger.warning(f"Device {device_ip} ISOLATED via gateway (REAL)")

                    if self.threat_logger:
                        self.threat_logger.log_action(
                            threat_id="manual",
                            action="isolate_device",
                            target=device_ip,
                            status="success",
                            details={"method": "iptables_block", "real_action": True}
                        )
                    return True
                else:
                    logger.error(f"Failed to isolate {device_ip} via gateway")
                    return False
            except Exception as e:
                logger.error(f"Gateway isolation error: {e}")
                return False

        # Standalone mode: simulated isolation (just update status)
        else:
            self.devices[device_ip].status = "isolated"
            logger.warning(f"Device {device_ip} marked as isolated (SIMULATED - no real traffic control)")

            if self.threat_logger:
                self.threat_logger.log_action(
                    threat_id="manual",
                    action="isolate_device",
                    target=device_ip,
                    status="success",
                    details={"method": "status_update", "real_action": False}
                )
            return True

    def unisolate_device(self, device_ip: str) -> bool:
        """
        Remove isolation from a device.

        Args:
            device_ip: IP address of device to unisolate

        Returns:
            True if successful
        """
        if device_ip not in self.devices:
            logger.warning(f"Device {device_ip} not found")
            return False

        # Gateway mode: real unisolation
        if self.gateway and self.gateway.is_gateway_mode:
            success = self.gateway.unisolate_device(device_ip)
            if success:
                self.devices[device_ip].status = "active"
                logger.info(f"Device {device_ip} unisolated via gateway")
                return True
            return False

        # Standalone mode
        self.devices[device_ip].status = "active"
        logger.info(f"Device {device_ip} marked as active (SIMULATED)")
        return True

    def get_device_for_morphing(self, device_type: str = None) -> Optional[Dict]:
        """
        Get device profile for honeypot morphing.

        Returns device characteristics that can be used to create
        a convincing honeypot clone.
        """
        with self._devices_lock:
            if device_type:
                for device in list(self.devices.values()):
                    if device.device_type == device_type:
                        return self._create_morph_profile(device)

            # Return random high-risk device
            high_risk = [d for d in list(self.devices.values()) if d.risk_score > 50]
            if high_risk:
                device = high_risk[0]
                return self._create_morph_profile(device)

        return None

    def _create_morph_profile(self, device: Device) -> Dict:
        """Create a morphing profile from a real device."""
        return {
            "device_type": device.device_type,
            "manufacturer": device.manufacturer,
            "os": device.os,
            "firmware": device.firmware,
            "services": device.services,
            "open_ports": device.open_ports,
            "mac_prefix": device.mac[:8] if device.mac else "AA:BB:CC",
            "banner_templates": self._get_banner_templates(device.device_type)
        }

    def _get_banner_templates(self, device_type: str) -> Dict[str, str]:
        """Get service banner templates for device type."""
        templates = {
            "wyze_cam": {
                "http": "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.35\r\n",
                "rtsp": "RTSP/1.0 200 OK\r\nServer: Wyze-RTSP/1.0\r\n",
                "telnet": "Wyze Cam v2\r\nLogin: "
            },
            "tp_link": {
                "http": "HTTP/1.1 200 OK\r\nServer: TP-Link HTTP Server\r\n",
                "telnet": "\r\nTP-LINK Wireless Router WR940N\r\nLogin: "
            },
            "samsung_tv": {
                "http": "HTTP/1.1 200 OK\r\nServer: Samsung TV Web\r\n",
                "upnp": "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n"
            }
        }
        return templates.get(device_type, {})

    def get_high_risk_devices(self, threshold: int = 60) -> List[Device]:
        """Get devices with risk score above threshold."""
        with self._devices_lock:
            return [d for d in list(self.devices.values()) if d.risk_score >= threshold]

    def get_statistics(self) -> Dict:
        """Get network statistics."""
        with self._devices_lock:
            devices = list(self.devices.values())
        return {
            "total_devices": len(devices),
            "active_devices": len([d for d in devices if d.status == "active"]),
            "isolated_devices": len([d for d in devices if d.status == "isolated"]),
            "high_risk_count": len([d for d in devices if d.risk_score >= 60]),
            "average_risk_score": sum(d.risk_score for d in devices) / len(devices) if devices else 0,
            "device_types": list(set(d.device_type for d in devices))
        }
