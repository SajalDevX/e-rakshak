"""
RAKSHAK Gateway Module
======================

Transforms RAKSHAK into an inline security gateway between modem and router.
Handles NAT, DHCP, routing, and provides full traffic control.

Architecture:
    INTERNET -> MODEM -> [RAKSHAK GATEWAY] -> ROUTER (AP Mode) -> Devices

Features:
- NAT (Network Address Translation)
- DHCP Server (via dnsmasq)
- IP Forwarding
- Deep Packet Inspection hook
- Device isolation via iptables
- Honeypot redirection via NAT
- Jetson Xavier NX platform optimization
"""

import os
import re
import subprocess
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum

from loguru import logger


class IsolationLevel(Enum):
    """Device isolation levels."""
    FULL = "full"                   # Block all traffic
    INTERNET_ONLY = "internet"      # Block internet, allow LAN
    RATE_LIMITED = "rate_limited"   # Apply rate limiting
    HONEYPOT = "honeypot"           # Redirect to honeypot


@dataclass
class NetworkInterface:
    """Represents a network interface"""
    name: str
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    mac_address: Optional[str] = None
    is_up: bool = False
    role: str = "unknown"  # "wan" or "lan"
    is_usb: bool = False   # Is this a USB ethernet adapter


@dataclass
class DHCPLease:
    """Represents a DHCP lease"""
    mac_address: str
    ip_address: str
    hostname: str
    lease_start: datetime
    lease_end: datetime
    is_active: bool = True


@dataclass
class IsolatedDevice:
    """Represents an isolated device."""
    ip_address: str
    mac_address: Optional[str]
    isolation_level: IsolationLevel
    isolated_at: datetime
    reason: str
    auto_expire: Optional[datetime] = None


@dataclass
class RedirectionRule:
    """Represents a honeypot redirection rule."""
    rule_id: str
    source_ip: str
    original_port: int
    honeypot_port: int
    protocol: str
    created_at: datetime


@dataclass
class GatewayConfig:
    """Gateway configuration"""
    wan_interface: str = "eth0"
    lan_interface: str = "eth1"
    lan_ip: str = "192.168.100.1"
    lan_netmask: str = "255.255.255.0"
    lan_network: str = "192.168.100.0/24"
    dhcp_enabled: bool = True  # Set False if NetworkManager handles DHCP
    dhcp_range_start: str = "192.168.100.10"
    dhcp_range_end: str = "192.168.100.250"
    dhcp_lease_time: str = "24h"
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    enable_ipv6: bool = False
    auto_detect_interfaces: bool = True
    usb_ethernet_patterns: List[str] = field(default_factory=lambda: ["eth1", "enx*", "enp*s*u*"])
    # LAN-to-LAN interception (KAVACH)
    lan_interception_enabled: bool = False
    # Bridge mode configuration (Layer-2 Bridge + Layer-3 Gateway)
    bridge_mode: bool = False
    bridge_name: str = "br0"
    bridge_members: List[str] = field(default_factory=list)
    bridge_nf_call_iptables: bool = True
    bridge_nf_call_arptables: bool = True
    proxy_arp_enabled: bool = True


class RakshakGateway:
    """
    RAKSHAK Gateway - Inline Security Gateway

    Positions RAKSHAK between modem and router for full traffic control.
    Provides real device isolation and honeypot redirection via iptables.
    """

    def __init__(self, config: Optional[GatewayConfig] = None):
        self.config = config or GatewayConfig()
        self.interfaces: Dict[str, NetworkInterface] = {}
        self.dhcp_leases: Dict[str, DHCPLease] = {}
        self.isolated_devices: Dict[str, IsolatedDevice] = {}
        self.redirection_rules: Dict[str, RedirectionRule] = {}
        self.is_running = False
        self.is_gateway_mode = False
        self.is_jetson = False
        self._original_lan_interface = None  # For bridge mode rollback

        # Paths
        self.dnsmasq_config_path = Path("/etc/dnsmasq.d/rakshak.conf")
        self.dhcp_leases_path = Path("/var/lib/misc/dnsmasq.leases")
        self.iptables_rules_path = Path("/etc/iptables/rakshak.rules")

        logger.info("RakshakGateway initialized")

    def detect_jetson_platform(self) -> bool:
        """
        Detect if running on Jetson platform.

        Returns:
            True if running on Jetson, False otherwise.
        """
        jetson_indicators = [
            "/etc/nv_tegra_release",
            "/usr/bin/jetson_clocks",
            "/sys/devices/gpu.0"
        ]

        for indicator in jetson_indicators:
            if os.path.exists(indicator):
                logger.info("Jetson platform detected")
                self.is_jetson = True
                return True

        logger.info("Non-Jetson platform (standard Linux)")
        self.is_jetson = False
        return False

    def detect_usb_ethernet(self) -> Optional[str]:
        """
        Detect USB-to-Ethernet adapter interface.

        USB ethernet adapters typically have names like:
        - eth1 (traditional naming)
        - enx<mac> (predictable naming based on MAC)
        - enp0s*u* (USB bus path naming)

        Returns:
            Interface name if found, None otherwise.
        """
        try:
            # Get all interfaces
            result = subprocess.run(
                ["ip", "-j", "link", "show"],
                capture_output=True, text=True, check=True
            )
            links = json.loads(result.stdout)

            usb_patterns = [
                r'^eth[1-9]$',           # eth1, eth2, etc.
                r'^enx[0-9a-f]{12}$',    # enx<mac_address>
                r'^enp\d+s\d+u\d+',      # USB path naming
                r'^ens\d+u\d+',          # Alternative USB naming
            ]

            for link in links:
                name = link.get("ifname", "")
                for pattern in usb_patterns:
                    if re.match(pattern, name, re.IGNORECASE):
                        logger.info(f"Detected USB ethernet adapter: {name}")
                        return name

            logger.warning("No USB ethernet adapter detected")
            return None

        except Exception as e:
            logger.error(f"Failed to detect USB ethernet: {e}")
            return None

    def detect_interfaces(self) -> Dict[str, NetworkInterface]:
        """Detect available network interfaces"""
        interfaces = {}

        try:
            # Get list of interfaces
            result = subprocess.run(
                ["ip", "-j", "link", "show"],
                capture_output=True, text=True, check=True
            )
            links = json.loads(result.stdout)

            for link in links:
                name = link.get("ifname", "")
                if name in ["lo", "docker0"] or name.startswith("veth"):
                    continue

                # Determine if this is a USB adapter
                is_usb = bool(re.match(r'^enx|^enp.*u|^eth[1-9]', name))

                iface = NetworkInterface(
                    name=name,
                    mac_address=link.get("address"),
                    is_up=link.get("operstate") == "UP",
                    is_usb=is_usb
                )

                # Get IP address
                ip_result = subprocess.run(
                    ["ip", "-j", "addr", "show", name],
                    capture_output=True, text=True
                )
                if ip_result.returncode == 0:
                    addr_info = json.loads(ip_result.stdout)
                    if addr_info and addr_info[0].get("addr_info"):
                        for addr in addr_info[0]["addr_info"]:
                            if addr.get("family") == "inet":
                                iface.ip_address = addr.get("local")
                                break

                interfaces[name] = iface

        except Exception as e:
            logger.error(f"Failed to detect interfaces: {e}")
            # Fallback: try common interface names
            for name in ["eth0", "eth1", "enp0s3", "enp0s8", "wlan0", "wlo1"]:
                try:
                    result = subprocess.run(
                        ["ip", "link", "show", name],
                        capture_output=True, text=True
                    )
                    if result.returncode == 0:
                        interfaces[name] = NetworkInterface(name=name)
                except:
                    pass

        self.interfaces = interfaces
        logger.info(f"Detected interfaces: {list(interfaces.keys())}")
        return interfaces

    def check_prerequisites(self) -> Tuple[bool, List[str]]:
        """Check if system meets gateway requirements"""
        issues = []

        # Check if running as root
        if os.geteuid() != 0:
            issues.append("Must run as root (sudo)")

        # Check for required tools
        required_tools = ["iptables", "dnsmasq", "ip", "sysctl"]
        for tool in required_tools:
            result = subprocess.run(["which", tool], capture_output=True)
            if result.returncode != 0:
                issues.append(f"Missing required tool: {tool}")

        # Check for two network interfaces
        self.detect_interfaces()
        ethernet_interfaces = [
            name for name, iface in self.interfaces.items()
            if name.startswith(("eth", "enp", "enx", "ens"))
        ]
        if len(ethernet_interfaces) < 2:
            issues.append(f"Need 2 ethernet interfaces, found: {ethernet_interfaces}")
            issues.append("Consider using USB-to-Ethernet adapter")

        # Check IP forwarding capability
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                current = f.read().strip()
                logger.debug(f"Current IP forwarding: {current}")
        except Exception as e:
            issues.append(f"Cannot read IP forwarding status: {e}")

        return len(issues) == 0, issues

    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding in kernel"""
        try:
            # Enable immediately
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                check=True, capture_output=True
            )

            # Make persistent
            sysctl_conf = "/etc/sysctl.d/99-rakshak.conf"
            with open(sysctl_conf, "w") as f:
                f.write("# RAKSHAK Gateway - IP Forwarding\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
                f.write("# Enable IPv4 forwarding (MANDATORY for gateway mode)\n")
                f.write("net.ipv4.ip_forward=1\n\n")
                f.write("# Disable IPv6 forwarding\n")
                f.write("net.ipv6.conf.all.forwarding=0\n\n")
                f.write("# Security settings\n")
                f.write("net.ipv4.conf.all.send_redirects=0\n")
                f.write("net.ipv4.conf.default.send_redirects=0\n")
                f.write("net.ipv4.conf.all.accept_redirects=0\n")
                f.write("net.ipv4.conf.default.accept_redirects=0\n")

            logger.info("IP forwarding enabled")
            return True

        except Exception as e:
            logger.error(f"Failed to enable IP forwarding: {e}")
            return False

    def configure_lan_interface(self) -> bool:
        """Configure LAN interface with static IP"""
        try:
            lan = self.config.lan_interface
            ip = self.config.lan_ip
            netmask = self.config.lan_netmask

            # Calculate prefix length from netmask
            prefix = sum(bin(int(x)).count('1') for x in netmask.split('.'))

            # Check if the IP is already assigned
            result = subprocess.run(
                ["ip", "addr", "show", lan], capture_output=True, text=True
            )
            if f"inet {ip}/{prefix}" in result.stdout:
                logger.info(f"IP {ip}/{prefix} is already assigned to {lan}")
                return True

            # Bring interface up first
            subprocess.run(
                ["ip", "link", "set", lan, "up"],
                capture_output=True
            )

            # Flush existing IPs
            subprocess.run(["ip", "addr", "flush", "dev", lan], capture_output=True)

            # Set new IP
            subprocess.run(
                ["ip", "addr", "add", f"{ip}/{prefix}", "dev", lan],
                check=True, capture_output=True
            )

            logger.info(f"LAN interface {lan} configured with IP {ip}/{prefix}")
            return True

        except Exception as e:
            logger.error(f"Failed to configure LAN interface: {e}")
            return False

    def setup_bridge(self) -> bool:
        """
        Create and configure Linux bridge for Layer-2 + Layer-3 operation.

        This enables:
        - Transparent Layer-2 forwarding (sees all ARP, broadcast traffic)
        - Layer-3 gateway functionality (NAT, firewall)
        - Passive discovery of static IP devices via SSDP, ONVIF, ARP

        Returns:
            True if bridge setup successful, False otherwise.
        """
        if not self.config.bridge_mode:
            logger.info("Bridge mode disabled, using direct interface")
            return True

        bridge = self.config.bridge_name
        members = self.config.bridge_members or [self.config.lan_interface]

        try:
            # Save original interface for rollback
            self._original_lan_interface = self.config.lan_interface

            # Step 1: Load bridge kernel module
            subprocess.run(["modprobe", "br_netfilter"], capture_output=True)
            subprocess.run(["modprobe", "bridge"], capture_output=True)

            # Step 2: Enable kernel settings for bridge
            kernel_settings = [
                ("net.ipv4.ip_forward", "1"),
                ("net.bridge.bridge-nf-call-iptables", "1" if self.config.bridge_nf_call_iptables else "0"),
                ("net.bridge.bridge-nf-call-arptables", "1" if self.config.bridge_nf_call_arptables else "0"),
                ("net.ipv4.conf.all.proxy_arp", "1" if self.config.proxy_arp_enabled else "0"),
            ]

            for key, value in kernel_settings:
                result = subprocess.run(
                    ["sysctl", "-w", f"{key}={value}"],
                    capture_output=True
                )
                if result.returncode != 0:
                    logger.warning(f"Failed to set {key}={value} (may need bridge to exist first)")

            # Step 3: Check if bridge already exists
            result = subprocess.run(["ip", "link", "show", bridge], capture_output=True)
            bridge_exists = result.returncode == 0

            if not bridge_exists:
                # Step 4: Remove IP from member interface(s)
                for member in members:
                    subprocess.run(["ip", "addr", "flush", "dev", member], capture_output=True)

                # Step 5: Create bridge
                subprocess.run(
                    ["ip", "link", "add", "name", bridge, "type", "bridge"],
                    check=True, capture_output=True
                )
                logger.info(f"Bridge {bridge} created")

                # Step 6: Add member interface(s) to bridge
                for member in members:
                    subprocess.run(
                        ["ip", "link", "set", member, "master", bridge],
                        check=True, capture_output=True
                    )
                    subprocess.run(
                        ["ip", "link", "set", member, "up"],
                        check=True, capture_output=True
                    )
                    logger.info(f"Added {member} to bridge {bridge}")

                # Step 7: Bring bridge up
                subprocess.run(
                    ["ip", "link", "set", bridge, "up"],
                    check=True, capture_output=True
                )

            # Step 8: Assign IP to bridge
            prefix = sum(bin(int(x)).count('1') for x in self.config.lan_netmask.split('.'))
            ip_cidr = f"{self.config.lan_ip}/{prefix}"

            # Check if IP already assigned
            result = subprocess.run(
                ["ip", "addr", "show", bridge], capture_output=True, text=True
            )
            if ip_cidr not in result.stdout:
                subprocess.run(
                    ["ip", "addr", "add", ip_cidr, "dev", bridge],
                    check=True, capture_output=True
                )
                logger.info(f"Assigned {ip_cidr} to bridge {bridge}")

            # Step 9: Update lan_interface to use bridge
            self.config.lan_interface = bridge

            # Step 10: Re-apply bridge-nf settings now that bridge exists
            for key, value in kernel_settings:
                subprocess.run(["sysctl", "-w", f"{key}={value}"], capture_output=True)

            # Also set proxy_arp on the bridge interface specifically
            subprocess.run(
                ["sysctl", "-w", f"net.ipv4.conf.{bridge}.proxy_arp=1"],
                capture_output=True
            )

            logger.info(f"Bridge {bridge} configured with members {members}")
            logger.info(f"Bridge IP: {self.config.lan_ip}/{prefix}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to setup bridge: {e}")
            return False
        except Exception as e:
            logger.error(f"Bridge setup error: {e}")
            return False

    def teardown_bridge(self) -> bool:
        """
        Remove Linux bridge and restore direct interface configuration.

        Returns:
            True if teardown successful, False otherwise.
        """
        if not self.config.bridge_mode:
            return True

        bridge = self.config.bridge_name

        try:
            # Determine original LAN interface
            if self._original_lan_interface:
                original_lan = self._original_lan_interface
            elif self.config.bridge_members:
                original_lan = self.config.bridge_members[0]
            else:
                original_lan = "eth1"

            logger.info(f"Tearing down bridge {bridge}, restoring to {original_lan}")

            # Step 1: Flush IP from bridge
            subprocess.run(["ip", "addr", "flush", "dev", bridge], capture_output=True)

            # Step 2: Remove members from bridge
            members = self.config.bridge_members or [original_lan]
            for member in members:
                subprocess.run(["ip", "link", "set", member, "nomaster"], capture_output=True)

            # Step 3: Delete bridge
            subprocess.run(["ip", "link", "set", bridge, "down"], capture_output=True)
            subprocess.run(["ip", "link", "delete", bridge, "type", "bridge"], capture_output=True)

            # Step 4: Restore IP to original interface
            prefix = sum(bin(int(x)).count('1') for x in self.config.lan_netmask.split('.'))
            subprocess.run(
                ["ip", "addr", "add", f"{self.config.lan_ip}/{prefix}", "dev", original_lan],
                capture_output=True
            )
            subprocess.run(["ip", "link", "set", original_lan, "up"], capture_output=True)

            # Step 5: Restore lan_interface config
            self.config.lan_interface = original_lan
            self._original_lan_interface = None

            logger.info(f"Bridge {bridge} removed, restored to {original_lan}")
            return True

        except Exception as e:
            logger.error(f"Bridge teardown error: {e}")
            return False

    def setup_firewall_chains(self) -> bool:
        """
        Setup dedicated iptables chains for RAKSHAK.

        Creates organized chain structure:
        - RAKSHAK_FORWARD: Main forwarding decisions
        - RAKSHAK_ISOLATED: Isolated device rules
        - RAKSHAK_HONEYPOT: Honeypot redirection rules
        - RAKSHAK_RATELIMIT: Rate limiting rules
        """
        try:
            chains = [
                ("filter", "RAKSHAK_FORWARD"),
                ("filter", "RAKSHAK_ISOLATED"),
                ("filter", "RAKSHAK_RATELIMIT"),
                ("nat", "RAKSHAK_HONEYPOT"),
            ]

            for table, chain in chains:
                # Create chain (ignore error if exists)
                subprocess.run(
                    ["iptables", "-t", table, "-N", chain],
                    capture_output=True
                )

                # Flush existing rules
                subprocess.run(
                    ["iptables", "-t", table, "-F", chain],
                    capture_output=True
                )

            # Insert jumps to our chains at the beginning of built-in chains
            # Order: ISOLATED -> RATELIMIT -> FORWARD

            subprocess.run([
                "iptables", "-I", "FORWARD", "1",
                "-j", "RAKSHAK_ISOLATED"
            ], capture_output=True)

            subprocess.run([
                "iptables", "-I", "FORWARD", "2",
                "-j", "RAKSHAK_RATELIMIT"
            ], capture_output=True)

            subprocess.run([
                "iptables", "-I", "FORWARD", "3",
                "-j", "RAKSHAK_FORWARD"
            ], capture_output=True)

            # NAT PREROUTING: jump to RAKSHAK_HONEYPOT
            subprocess.run([
                "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                "-j", "RAKSHAK_HONEYPOT"
            ], capture_output=True)

            logger.info("RAKSHAK firewall chains configured")
            return True

        except Exception as e:
            logger.error(f"Failed to setup firewall chains: {e}")
            return False

    def cleanup_firewall_chains(self) -> bool:
        """Remove RAKSHAK firewall chains."""
        try:
            chains = [
                ("filter", "RAKSHAK_FORWARD"),
                ("filter", "RAKSHAK_ISOLATED"),
                ("filter", "RAKSHAK_RATELIMIT"),
                ("nat", "RAKSHAK_HONEYPOT"),
            ]

            # Remove jumps first (try multiple times)
            for _ in range(10):
                subprocess.run([
                    "iptables", "-D", "FORWARD",
                    "-j", "RAKSHAK_ISOLATED"
                ], capture_output=True)
                subprocess.run([
                    "iptables", "-D", "FORWARD",
                    "-j", "RAKSHAK_RATELIMIT"
                ], capture_output=True)
                subprocess.run([
                    "iptables", "-D", "FORWARD",
                    "-j", "RAKSHAK_FORWARD"
                ], capture_output=True)
                subprocess.run([
                    "iptables", "-t", "nat", "-D", "PREROUTING",
                    "-j", "RAKSHAK_HONEYPOT"
                ], capture_output=True)

            # Flush and delete chains
            for table, chain in chains:
                subprocess.run(
                    ["iptables", "-t", table, "-F", chain],
                    capture_output=True
                )
                subprocess.run(
                    ["iptables", "-t", table, "-X", chain],
                    capture_output=True
                )

            logger.info("RAKSHAK firewall chains removed")
            return True

        except Exception as e:
            logger.error(f"Failed to cleanup firewall chains: {e}")
            return False

    def setup_nat(self) -> bool:
        """Setup NAT (Network Address Translation) rules"""
        try:
            wan = self.config.wan_interface
            lan = self.config.lan_interface

            # If DHCP is disabled, NetworkManager handles NAT - don't flush its rules
            if self.config.dhcp_enabled:
                # Flush existing NAT rules (only if we manage DHCP)
                subprocess.run(["iptables", "-t", "nat", "-F", "POSTROUTING"], capture_output=True)

                # Masquerade outgoing traffic on WAN
                subprocess.run([
                    "iptables", "-t", "nat", "-A", "POSTROUTING",
                    "-o", wan, "-j", "MASQUERADE"
                ], check=True, capture_output=True)

                # Set default FORWARD policy to DROP (only when we manage everything)
                subprocess.run([
                    "iptables", "-P", "FORWARD", "DROP"
                ], capture_output=True)
            else:
                logger.info("DHCP disabled - preserving NetworkManager NAT rules")
                # Don't set FORWARD to DROP - let NetworkManager handle it
                # Just verify NAT is working
                result = subprocess.run(
                    ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n"],
                    capture_output=True, text=True
                )
                if "MASQUERADE" in result.stdout:
                    logger.info("NetworkManager NAT (MASQUERADE) detected")
                else:
                    logger.warning("No MASQUERADE rule found - internet may not work")

            # Allow forwarding from LAN to WAN (in our chain)
            subprocess.run([
                "iptables", "-A", "RAKSHAK_FORWARD",
                "-i", lan, "-o", wan,
                "-j", "ACCEPT"
            ], check=True, capture_output=True)

            # Allow established connections back
            subprocess.run([
                "iptables", "-A", "RAKSHAK_FORWARD",
                "-i", wan, "-o", lan,
                "-m", "state", "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT"
            ], check=True, capture_output=True)

            # LAN-to-LAN forwarding (for KAVACH ARP interception)
            # When KAVACH is active, internal traffic arrives at gateway and needs
            # to be forwarded back out to the real destination on the same interface
            if self.config.lan_interception_enabled:
                # Log internal traffic for monitoring
                subprocess.run([
                    "iptables", "-A", "RAKSHAK_FORWARD",
                    "-i", lan, "-o", lan,
                    "-j", "LOG", "--log-prefix", "[RAKSHAK-INTERNAL] ", "--log-level", "4"
                ], capture_output=True)

                # Allow LAN-to-LAN forwarding
                subprocess.run([
                    "iptables", "-A", "RAKSHAK_FORWARD",
                    "-i", lan, "-o", lan,
                    "-j", "ACCEPT"
                ], check=True, capture_output=True)

                logger.info("KAVACH: LAN-to-LAN forwarding enabled")

            # Allow DHCP on LAN
            subprocess.run([
                "iptables", "-A", "INPUT",
                "-i", lan, "-p", "udp", "--dport", "67:68",
                "-j", "ACCEPT"
            ], capture_output=True)

            # Allow DNS on LAN
            subprocess.run([
                "iptables", "-A", "INPUT",
                "-i", lan, "-p", "udp", "--dport", "5353",
                "-j", "ACCEPT"
            ], capture_output=True)

            # Log dashboard access attempts for threat monitoring
            subprocess.run([
                "iptables", "-A", "INPUT",
                "-p", "tcp", "--dport", "5000", "--syn",
                "-j", "LOG", "--log-prefix", "[RAKSHAK-DASHBOARD] ", "--log-level", "4"
            ], capture_output=True)

            # Allow RAKSHAK dashboard
            subprocess.run([
                "iptables", "-A", "INPUT",
                "-p", "tcp", "--dport", "5000",
                "-j", "ACCEPT"
            ], capture_output=True)

            # Allow honeypot ports
            for port in [2222, 2323, 8080]:
                subprocess.run([
                    "iptables", "-A", "INPUT",
                    "-p", "tcp", "--dport", str(port),
                    "-j", "ACCEPT"
                ], capture_output=True)

            logger.info("NAT rules configured")
            return True

        except Exception as e:
            logger.error(f"Failed to setup NAT: {e}")
            return False

    def configure_dnsmasq(self) -> bool:
        """Configure dnsmasq for DHCP and DNS"""
        # Skip if DHCP is disabled (NetworkManager handles it)
        if not self.config.dhcp_enabled:
            logger.info("DHCP disabled - skipping dnsmasq configuration (NetworkManager mode)")
            return True

        try:
            config_content = f"""# RAKSHAK Gateway - DHCP/DNS Configuration
# Generated: {datetime.now().isoformat()}

# Interface to serve DHCP on
interface={self.config.lan_interface}
bind-interfaces

# Don't use /etc/resolv.conf
no-resolv

# Upstream DNS servers
server={self.config.dns_servers[0]}
server={self.config.dns_servers[1] if len(self.config.dns_servers) > 1 else '1.1.1.1'}

# DHCP range
dhcp-range={self.config.dhcp_range_start},{self.config.dhcp_range_end},{self.config.dhcp_lease_time}

# Gateway (this device)
dhcp-option=option:router,{self.config.lan_ip}

# DNS server (this device)
dhcp-option=option:dns-server,{self.config.lan_ip}

# Domain
domain=rakshak.local
local=/rakshak.local/

# Log DHCP queries
log-dhcp

# Lease file location
dhcp-leasefile=/var/lib/misc/dnsmasq.leases

# Don't read /etc/hosts
no-hosts

# Expand hosts with domain
expand-hosts
"""

            # Ensure directory exists
            self.dnsmasq_config_path.parent.mkdir(parents=True, exist_ok=True)

            # Write config
            with open(self.dnsmasq_config_path, "w") as f:
                f.write(config_content)

            # Ensure lease file directory exists
            self.dhcp_leases_path.parent.mkdir(parents=True, exist_ok=True)
            self.dhcp_leases_path.touch(exist_ok=True)

            # Enable and restart dnsmasq
            subprocess.run(["systemctl", "enable", "dnsmasq"], capture_output=True)
            subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)

            # Verify
            time.sleep(1)
            result = subprocess.run(
                ["systemctl", "is-active", "dnsmasq"],
                capture_output=True, text=True
            )
            if result.stdout.strip() == "active":
                logger.info("dnsmasq configured and running")
                return True
            else:
                logger.error("dnsmasq failed to start")
                return False

        except Exception as e:
            logger.error(f"Failed to configure dnsmasq: {e}")
            return False

    def start_gateway(self) -> bool:
        """
        Start RAKSHAK gateway mode.

        This transforms the Jetson into the network gateway:
        1. Verify prerequisites (2 NICs, root, tools)
        2. Configure LAN interface with static IP
        3. Enable IP forwarding
        4. Setup firewall chains
        5. Setup NAT rules
        6. Start DHCP server
        7. Start lease monitoring
        """
        logger.info("=" * 60)
        logger.info("Starting RAKSHAK Inline Security Gateway")
        logger.info("=" * 60)

        # Step 1: Check prerequisites
        ready, issues = self.check_prerequisites()
        if not ready:
            logger.error("Prerequisites not met:")
            for issue in issues:
                logger.error(f"  - {issue}")
            return False

        # Detect Jetson platform
        self.detect_jetson_platform()

        # Auto-detect USB ethernet if needed
        if self.config.lan_interface == "auto" or self.config.auto_detect_interfaces:
            detected = self.detect_usb_ethernet()
            if detected:
                self.config.lan_interface = detected
                logger.info(f"Auto-detected LAN interface: {detected}")
            elif self.config.lan_interface == "auto":
                logger.error("Failed to auto-detect USB ethernet adapter")
                return False

        # Step 2: Setup bridge if enabled (before IP forwarding)
        if self.config.bridge_mode:
            logger.info("Setting up Layer-2 bridge...")
            if not self.setup_bridge():
                logger.warning("Bridge setup failed, falling back to direct interface mode")
                self.config.bridge_mode = False
            else:
                logger.info(f"Bridge mode active: {self.config.bridge_name}")

        # Step 3: Enable IP forwarding
        logger.info("Enabling IP forwarding...")
        if not self.enable_ip_forwarding():
            return False

        # Step 4: Configure LAN interface (skipped if bridge mode - IP already on bridge)
        if not self.config.bridge_mode:
            logger.info(f"Configuring LAN interface {self.config.lan_interface}...")
            if not self.configure_lan_interface():
                return False
        else:
            logger.info(f"LAN interface is bridge {self.config.lan_interface} (already configured)")

        # Step 5: Setup firewall chains
        logger.info("Setting up firewall chains...")
        if not self.setup_firewall_chains():
            return False

        # Step 6: Setup NAT
        logger.info("Setting up NAT rules...")
        if not self.setup_nat():
            return False

        # Step 7: Configure DHCP/DNS
        logger.info("Configuring DHCP server...")
        if not self.configure_dnsmasq():
            return False

        self.is_running = True
        self.is_gateway_mode = True

        # Step 8: Start DHCP lease monitor
        self._start_lease_monitor()

        logger.info("=" * 60)
        logger.info("RAKSHAK Gateway ACTIVE")
        logger.info(f"  WAN Interface: {self.config.wan_interface}")
        logger.info(f"  LAN Interface: {self.config.lan_interface}")
        if self.config.bridge_mode:
            logger.info(f"  Bridge Mode: ENABLED ({self.config.bridge_name})")
            if self._original_lan_interface:
                logger.info(f"  Bridge Members: {self._original_lan_interface}")
        logger.info(f"  Gateway IP: {self.config.lan_ip}")
        logger.info(f"  DHCP Range: {self.config.dhcp_range_start} - {self.config.dhcp_range_end}")
        logger.info(f"  Jetson Platform: {self.is_jetson}")
        logger.info("=" * 60)

        return True

    def stop_gateway(self) -> bool:
        """
        Stop gateway mode and cleanup.

        Cleanup order:
        1. Stop DHCP lease monitoring
        2. Remove all isolation rules
        3. Remove all redirection rules
        4. Remove firewall chains
        5. Teardown bridge (if bridge mode)
        6. Stop dnsmasq
        7. Remove configuration files
        """
        logger.info("Stopping RAKSHAK Gateway...")

        try:
            self.is_running = False

            # Remove isolation rules
            for ip in list(self.isolated_devices.keys()):
                self.unisolate_device(ip)

            # Remove redirection rules
            for rule_id, rule in list(self.redirection_rules.items()):
                self.remove_honeypot_redirection(rule.source_ip, rule.original_port)

            # Cleanup firewall chains
            self.cleanup_firewall_chains()

            # Teardown bridge if active
            if self.config.bridge_mode:
                logger.info("Tearing down bridge...")
                self.teardown_bridge()

            # Flush NAT rules
            subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
            subprocess.run(["iptables", "-F", "FORWARD"], capture_output=True)

            # Reset FORWARD policy
            subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)

            # Stop dnsmasq
            subprocess.run(["systemctl", "stop", "dnsmasq"], capture_output=True)

            # Remove config
            if self.dnsmasq_config_path.exists():
                self.dnsmasq_config_path.unlink()

            self.is_gateway_mode = False

            logger.info("RAKSHAK Gateway stopped successfully")
            return True

        except Exception as e:
            logger.error(f"Error stopping gateway: {e}")
            return False

    def _start_lease_monitor(self):
        """Start background thread to monitor DHCP leases"""
        def monitor():
            while self.is_running:
                self.refresh_dhcp_leases()
                self._check_isolation_expiry()
                time.sleep(30)  # Check every 30 seconds

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        logger.info("DHCP lease monitor started")

    def _check_isolation_expiry(self):
        """Check and remove expired isolation rules"""
        now = datetime.now()
        expired = [
            ip for ip, device in self.isolated_devices.items()
            if device.auto_expire and device.auto_expire < now
        ]
        for ip in expired:
            logger.info(f"Auto-expiring isolation for {ip}")
            self.unisolate_device(ip)

    def _check_device_reachable(self, ip_address: str) -> bool:
        """
        Check if a device is reachable by examining the ARP cache.

        A device is considered reachable if its ARP entry is REACHABLE, STALE, or DELAY.
        If the entry is INCOMPLETE or FAILED, the device is not on the network.
        """
        try:
            result = subprocess.run(
                ["ip", "neigh", "show", ip_address],
                capture_output=True, text=True, timeout=2
            )
            output = result.stdout.strip()

            if not output:
                return False

            # Check ARP state - REACHABLE, STALE, DELAY are OK; INCOMPLETE, FAILED are not
            if "REACHABLE" in output or "STALE" in output or "DELAY" in output or "PERMANENT" in output:
                return True
            elif "INCOMPLETE" in output or "FAILED" in output:
                return False

            # If we have a MAC address in the output, device was recently seen
            # Format: "10.42.0.72 dev enx... lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            if "lladdr" in output:
                return True

            return False

        except Exception as e:
            logger.debug(f"ARP check failed for {ip_address}: {e}")
            return True  # Assume active on error to avoid false negatives

    def refresh_dhcp_leases(self) -> Dict[str, DHCPLease]:
        """Refresh DHCP leases from dnsmasq and verify device connectivity"""
        try:
            if not self.dhcp_leases_path.exists():
                return self.dhcp_leases

            with open(self.dhcp_leases_path, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        timestamp, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]

                        # Verify device is actually reachable via ARP
                        is_reachable = self._check_device_reachable(ip)

                        lease = DHCPLease(
                            mac_address=mac,
                            ip_address=ip,
                            hostname=hostname if hostname != "*" else "unknown",
                            lease_start=datetime.fromtimestamp(int(timestamp) - 86400),
                            lease_end=datetime.fromtimestamp(int(timestamp)),
                            is_active=is_reachable
                        )
                        self.dhcp_leases[mac] = lease

                        if not is_reachable:
                            logger.debug(f"Device {hostname} ({ip}) has DHCP lease but is not reachable")

            logger.debug(f"Refreshed {len(self.dhcp_leases)} DHCP leases")

        except Exception as e:
            logger.error(f"Failed to refresh DHCP leases: {e}")

        return self.dhcp_leases

    def get_connected_devices(self) -> List[Dict]:
        """Get list of devices from DHCP leases"""
        self.refresh_dhcp_leases()

        devices = []
        for mac, lease in self.dhcp_leases.items():
            is_isolated = lease.ip_address in self.isolated_devices
            devices.append({
                "mac": lease.mac_address,
                "ip": lease.ip_address,
                "hostname": lease.hostname,
                "lease_end": lease.lease_end.isoformat(),
                "is_active": lease.is_active,
                "is_isolated": is_isolated,
                "isolation_level": self.isolated_devices[lease.ip_address].isolation_level.value if is_isolated else None
            })

        return devices

    def _get_mac_for_ip(self, ip_address: str) -> Optional[str]:
        """Get MAC address for an IP from DHCP leases."""
        for mac, lease in self.dhcp_leases.items():
            if lease.ip_address == ip_address:
                return mac
        return None

    def isolate_device(self, ip_address: str,
                       level: IsolationLevel = IsolationLevel.FULL,
                       reason: str = "Threat detected",
                       duration_minutes: Optional[int] = None) -> bool:
        """
        Isolate a device with configurable isolation levels.

        Args:
            ip_address: IP address of device to isolate
            level: Isolation level (FULL, INTERNET_ONLY, RATE_LIMITED, HONEYPOT)
            reason: Reason for isolation (for logging)
            duration_minutes: Auto-expire after N minutes (None = permanent)

        Returns:
            True if isolation successful, False otherwise.
        """
        try:
            if level == IsolationLevel.FULL:
                # Block ALL traffic from/to device
                # Note: -m comment must come before -j DROP (iptables syntax requirement)
                subprocess.run([
                    "iptables", "-I", "RAKSHAK_ISOLATED", "1",
                    "-s", ip_address,
                    "-m", "comment", "--comment", f"rakshak-isolate-{ip_address}",
                    "-j", "DROP"
                ], check=True, capture_output=True)

                subprocess.run([
                    "iptables", "-I", "RAKSHAK_ISOLATED", "1",
                    "-d", ip_address,
                    "-m", "comment", "--comment", f"rakshak-isolate-{ip_address}",
                    "-j", "DROP"
                ], check=True, capture_output=True)

                logger.critical(f"Device {ip_address} FULLY ISOLATED - {reason}")

            elif level == IsolationLevel.INTERNET_ONLY:
                # Block internet access but allow LAN communication
                wan = self.config.wan_interface

                subprocess.run([
                    "iptables", "-I", "RAKSHAK_ISOLATED", "1",
                    "-s", ip_address, "-o", wan,
                    "-m", "comment", "--comment", f"rakshak-isolate-wan-{ip_address}",
                    "-j", "DROP"
                ], check=True, capture_output=True)

                logger.warning(f"Device {ip_address} INTERNET BLOCKED - {reason}")

            elif level == IsolationLevel.RATE_LIMITED:
                # Apply rate limiting
                subprocess.run([
                    "iptables", "-I", "RAKSHAK_RATELIMIT", "1",
                    "-s", ip_address,
                    "-m", "limit", "--limit", "10/second", "--limit-burst", "20",
                    "-m", "comment", "--comment", f"rakshak-ratelimit-{ip_address}",
                    "-j", "ACCEPT"
                ], check=True, capture_output=True)

                subprocess.run([
                    "iptables", "-I", "RAKSHAK_RATELIMIT", "2",
                    "-s", ip_address,
                    "-m", "comment", "--comment", f"rakshak-ratelimit-drop-{ip_address}",
                    "-j", "DROP"
                ], check=True, capture_output=True)

                logger.warning(f"Device {ip_address} RATE LIMITED - {reason}")

            elif level == IsolationLevel.HONEYPOT:
                # Will be handled by redirect_to_honeypot
                logger.info(f"Device {ip_address} marked for honeypot redirection")

            # Track isolated device
            expire_time = None
            if duration_minutes:
                expire_time = datetime.now() + timedelta(minutes=duration_minutes)

            self.isolated_devices[ip_address] = IsolatedDevice(
                ip_address=ip_address,
                mac_address=self._get_mac_for_ip(ip_address),
                isolation_level=level,
                isolated_at=datetime.now(),
                reason=reason,
                auto_expire=expire_time
            )

            return True

        except Exception as e:
            logger.error(f"Failed to isolate device {ip_address}: {e}")
            return False

    def unisolate_device(self, ip_address: str) -> bool:
        """Remove isolation from a device"""
        try:
            # Remove all rules for this IP from RAKSHAK_ISOLATED
            for _ in range(10):
                result = subprocess.run([
                    "iptables", "-D", "RAKSHAK_ISOLATED",
                    "-s", ip_address, "-j", "DROP"
                ], capture_output=True)
                if result.returncode != 0:
                    break

            for _ in range(10):
                result = subprocess.run([
                    "iptables", "-D", "RAKSHAK_ISOLATED",
                    "-d", ip_address, "-j", "DROP"
                ], capture_output=True)
                if result.returncode != 0:
                    break

            # Remove from RATELIMIT chain
            for _ in range(10):
                result = subprocess.run([
                    "iptables", "-D", "RAKSHAK_RATELIMIT",
                    "-s", ip_address
                ], capture_output=True)
                if result.returncode != 0:
                    break

            # Remove from tracking
            if ip_address in self.isolated_devices:
                del self.isolated_devices[ip_address]

            logger.info(f"Device {ip_address} isolation removed")
            return True

        except Exception as e:
            logger.error(f"Failed to unisolate device {ip_address}: {e}")
            return False

    def redirect_to_honeypot(self, source_ip: str,
                             original_port: int,
                             honeypot_port: int,
                             protocol: str = "tcp",
                             honeypot_ip: str = None) -> bool:
        """
        Redirect traffic from source to honeypot using NAT.

        Supports two modes:
        - Local redirect (REDIRECT): honeypot_ip is None or localhost
        - Remote redirect (DNAT): honeypot_ip is external address

        Args:
            source_ip: IP address of attacker to redirect
            original_port: Port attacker is targeting
            honeypot_port: Port where honeypot is listening
            protocol: tcp or udp
            honeypot_ip: IP of honeypot (None = local)

        Returns:
            True if redirection setup successful, False otherwise.
        """
        try:
            rule_id = f"hp-{source_ip}-{original_port}-{honeypot_port}"

            if honeypot_ip is None or honeypot_ip in ["127.0.0.1", self.config.lan_ip, "localhost"]:
                # Local redirect using REDIRECT target
                subprocess.run([
                    "iptables", "-t", "nat", "-I", "RAKSHAK_HONEYPOT", "1",
                    "-s", source_ip,
                    "-p", protocol,
                    "--dport", str(original_port),
                    "-j", "REDIRECT",
                    "--to-port", str(honeypot_port),
                    "-m", "comment", "--comment", f"rakshak-{rule_id}"
                ], check=True, capture_output=True)

                logger.info(f"Traffic from {source_ip}:{original_port} REDIRECTED to local honeypot:{honeypot_port}")

            else:
                # Remote redirect using DNAT
                subprocess.run([
                    "iptables", "-t", "nat", "-I", "RAKSHAK_HONEYPOT", "1",
                    "-s", source_ip,
                    "-p", protocol,
                    "--dport", str(original_port),
                    "-j", "DNAT",
                    "--to-destination", f"{honeypot_ip}:{honeypot_port}",
                    "-m", "comment", "--comment", f"rakshak-{rule_id}"
                ], check=True, capture_output=True)

                logger.info(f"Traffic from {source_ip}:{original_port} REDIRECTED to {honeypot_ip}:{honeypot_port}")

            # Track redirection
            self.redirection_rules[rule_id] = RedirectionRule(
                rule_id=rule_id,
                source_ip=source_ip,
                original_port=original_port,
                honeypot_port=honeypot_port,
                protocol=protocol,
                created_at=datetime.now()
            )

            return True

        except Exception as e:
            logger.error(f"Failed to setup honeypot redirection: {e}")
            return False

    def remove_honeypot_redirection(self, source_ip: str, original_port: int) -> bool:
        """Remove honeypot redirection rule."""
        try:
            # Find rule ID pattern
            pattern = f"hp-{source_ip}-{original_port}"

            # Try to delete rules matching the pattern
            for _ in range(5):
                result = subprocess.run(
                    ["iptables", "-t", "nat", "-L", "RAKSHAK_HONEYPOT", "-n", "--line-numbers"],
                    capture_output=True, text=True
                )

                found = False
                for line in result.stdout.split("\n"):
                    if f"rakshak-{pattern}" in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            line_num = parts[0]
                            subprocess.run([
                                "iptables", "-t", "nat", "-D", "RAKSHAK_HONEYPOT", line_num
                            ], capture_output=True)
                            found = True
                            break

                if not found:
                    break

            # Remove from tracking
            rules_to_remove = [
                rule_id for rule_id in self.redirection_rules
                if rule_id.startswith(pattern)
            ]
            for rule_id in rules_to_remove:
                del self.redirection_rules[rule_id]

            logger.info(f"Honeypot redirection removed for {source_ip}:{original_port}")
            return True

        except Exception as e:
            logger.error(f"Failed to remove honeypot redirection: {e}")
            return False

    def rate_limit_device(self, ip_address: str, limit: str = "100/sec") -> bool:
        """Apply rate limiting to a device"""
        return self.isolate_device(ip_address, IsolationLevel.RATE_LIMITED, f"Rate limited to {limit}")

    def block_domain(self, domain: str) -> bool:
        """Block a domain via DNS sinkhole"""
        try:
            # Add to dnsmasq blocklist
            blocklist_path = Path("/etc/dnsmasq.d/rakshak-blocklist.conf")

            # Read existing blocklist
            existing = set()
            if blocklist_path.exists():
                with open(blocklist_path, "r") as f:
                    for line in f:
                        if line.startswith("address=/"):
                            existing.add(line.strip())

            # Add new domain
            new_entry = f"address=/{domain}/0.0.0.0"
            if new_entry not in existing:
                with open(blocklist_path, "a") as f:
                    f.write(f"{new_entry}\n")

                # Restart dnsmasq to apply
                subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)

            logger.info(f"Domain {domain} blocked")
            return True

        except Exception as e:
            logger.error(f"Failed to block domain {domain}: {e}")
            return False

    def get_traffic_stats(self) -> Dict:
        """Get traffic statistics from iptables"""
        stats = {
            "total_forwarded_packets": 0,
            "total_forwarded_bytes": 0,
            "blocked_packets": 0,
            "isolated_devices": len(self.isolated_devices),
            "active_redirections": len(self.redirection_rules),
            "nat_translations": 0
        }

        try:
            # Get FORWARD chain stats
            result = subprocess.run(
                ["iptables", "-L", "RAKSHAK_FORWARD", "-v", "-n", "-x"],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        packets = int(parts[0])
                        bytes_count = int(parts[1])
                        stats["total_forwarded_packets"] += packets
                        stats["total_forwarded_bytes"] += bytes_count

            # Get ISOLATED chain stats
            result = subprocess.run(
                ["iptables", "-L", "RAKSHAK_ISOLATED", "-v", "-n", "-x"],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        stats["blocked_packets"] += int(parts[0])

            # Get NAT stats
            result = subprocess.run(
                ["iptables", "-t", "nat", "-L", "-v", "-n", "-x"],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        stats["nat_translations"] += int(parts[0])

        except Exception as e:
            logger.error(f"Failed to get traffic stats: {e}")

        return stats

    def get_status(self) -> Dict:
        """Get gateway status"""
        status = {
            "is_running": self.is_running,
            "is_gateway_mode": self.is_gateway_mode,
            "is_jetson": self.is_jetson,
            "wan_interface": self.config.wan_interface,
            "lan_interface": self.config.lan_interface,
            "lan_ip": self.config.lan_ip,
            "dhcp_range": f"{self.config.dhcp_range_start} - {self.config.dhcp_range_end}",
            "connected_devices": len(self.dhcp_leases),
            "isolated_devices": len(self.isolated_devices),
            "active_redirections": len(self.redirection_rules),
            "traffic_stats": self.get_traffic_stats()
        }

        # Add bridge mode information
        if self.config.bridge_mode:
            status["bridge_mode"] = True
            status["bridge_name"] = self.config.bridge_name
            status["bridge_members"] = self.config.bridge_members
        else:
            status["bridge_mode"] = False

        return status


# Convenience function to create gateway with config from YAML
def create_gateway_from_config(config_dict: Dict) -> RakshakGateway:
    """Create gateway from configuration dictionary"""
    gateway_config = config_dict.get("gateway", {})

    # Handle nested DHCP config
    dhcp_config = gateway_config.get("dhcp", {})

    # Handle lan_interception config
    lan_interception_config = gateway_config.get("lan_interception", {})

    # Handle bridge mode config
    bridge_config = gateway_config.get("bridge", {})

    # Determine bridge members - default to lan_interface if not specified
    lan_interface = gateway_config.get("lan_interface", "eth1")
    bridge_members = bridge_config.get("members", [])
    if not bridge_members and bridge_config.get("enabled", False):
        bridge_members = [lan_interface]

    config = GatewayConfig(
        wan_interface=gateway_config.get("wan_interface", "eth0"),
        lan_interface=lan_interface,
        lan_ip=gateway_config.get("lan_ip", "192.168.100.1"),
        lan_netmask=gateway_config.get("lan_netmask", "255.255.255.0"),
        lan_network=gateway_config.get("lan_network", "192.168.100.0/24"),
        dhcp_enabled=dhcp_config.get("enabled", gateway_config.get("dhcp_enabled", True)),
        dhcp_range_start=dhcp_config.get("range_start", gateway_config.get("dhcp_range_start", "192.168.100.10")),
        dhcp_range_end=dhcp_config.get("range_end", gateway_config.get("dhcp_range_end", "192.168.100.250")),
        dhcp_lease_time=dhcp_config.get("lease_time", gateway_config.get("dhcp_lease_time", "24h")),
        dns_servers=gateway_config.get("dns", {}).get("servers", gateway_config.get("dns_servers", ["8.8.8.8", "1.1.1.1"])),
        auto_detect_interfaces=gateway_config.get("auto_detect_interfaces", True),
        usb_ethernet_patterns=gateway_config.get("usb_ethernet_patterns", ["eth1", "enx*", "enp*s*u*"]),
        lan_interception_enabled=lan_interception_config.get("enabled", False),
        # Bridge mode configuration
        bridge_mode=bridge_config.get("enabled", False),
        bridge_name=bridge_config.get("name", "br0"),
        bridge_members=bridge_members,
        bridge_nf_call_iptables=bridge_config.get("nf_call_iptables", True),
        bridge_nf_call_arptables=bridge_config.get("nf_call_arptables", True),
        proxy_arp_enabled=bridge_config.get("proxy_arp", True)
    )

    return RakshakGateway(config)


if __name__ == "__main__":
    # Test gateway setup
    gateway = RakshakGateway()

    print("Detecting Jetson platform...")
    is_jetson = gateway.detect_jetson_platform()
    print(f"Jetson platform: {is_jetson}")

    print("\nDetecting USB ethernet...")
    usb_eth = gateway.detect_usb_ethernet()
    print(f"USB ethernet: {usb_eth}")

    print("\nChecking prerequisites...")
    ready, issues = gateway.check_prerequisites()

    if ready:
        print("\nAll prerequisites met!")
        print("Run 'sudo python -m core.gateway' to test gateway mode")
    else:
        print("\nPrerequisites not met:")
        for issue in issues:
            print(f"  - {issue}")
