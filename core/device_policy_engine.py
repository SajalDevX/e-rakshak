#!/usr/bin/env python3
"""
Device Policy Engine
====================

Defines and enforces per-device-type security policies.

Each device type has:
- Allowed zones
- Permitted protocols and ports
- Rate limits
- DNS domain whitelist
- Behavioral constraints
- Lateral movement restrictions

These policies are enforced through:
- iptables rules (gateway.py)
- DNS whitelisting (dns_whitelist_manager.py)
- Zone assignment (automatic_zone_manager.py)

Author: Team RAKSHAK
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from loguru import logger


class ProtocolType(Enum):
    """Network protocol types."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"


@dataclass
class PortRule:
    """Port access rule."""
    protocol: str  # tcp, udp, icmp
    port: int = 0  # 0 = any
    direction: str = "outbound"  # outbound, inbound, both
    description: str = ""


@dataclass
class RateLimit:
    """Rate limiting configuration."""
    max_connections_per_second: int = 100
    max_bandwidth_mbps: int = 10
    max_dns_queries_per_minute: int = 60


@dataclass
class DevicePolicy:
    """Security policy for a device type."""
    device_type: str
    allowed_zones: List[str] = field(default_factory=list)
    permitted_protocols: List[str] = field(default_factory=list)
    permitted_ports: List[PortRule] = field(default_factory=list)
    dns_whitelist_patterns: List[str] = field(default_factory=list)
    rate_limits: Optional[RateLimit] = None
    allow_iot_lateral: bool = False  # CRITICAL: Block IoT-to-IoT by default
    allow_internet: bool = True
    allow_lan: bool = False  # Restrict LAN access by default
    require_cloud_only: bool = True  # Only allow cloud endpoints
    behavioral_constraints: Dict[str, any] = field(default_factory=dict)


class DevicePolicyEngine:
    """
    Manages device type policies for zero-trust enforcement.

    Provides:
    - Pre-defined policies for common IoT devices
    - Custom policy creation
    - Policy lookup and enforcement
    - Policy violation detection
    """

    def __init__(self, config: dict):
        """
        Initialize device policy engine.

        Args:
            config: Configuration dictionary
        """
        self.config = config

        # Load policies from config or use defaults
        policy_config = config.get("zero_trust", {}).get("device_policies", {})
        self.policies: Dict[str, DevicePolicy] = {}

        # Initialize default policies
        self._init_default_policies()

        # Override with config policies
        self._load_config_policies(policy_config)

        logger.info(f"DevicePolicyEngine initialized with {len(self.policies)} policies")

    def _init_default_policies(self):
        """Initialize default security policies for common device types."""

        # ==================== IoT CAMERAS ====================
        self.policies["camera"] = DevicePolicy(
            device_type="camera",
            allowed_zones=["iot"],
            permitted_protocols=["tcp", "udp"],
            permitted_ports=[
                PortRule("tcp", 443, "outbound", "HTTPS to cloud"),
                PortRule("udp", 53, "outbound", "DNS"),
                PortRule("udp", 123, "outbound", "NTP time sync"),
            ],
            dns_whitelist_patterns=[
                r".*\.wyze\.com$",
                r".*\.wyzecam\.com$",
                r".*\.nest\.com$",
                r".*\.ring\.com$",
                r".*\.hik-connect\.com$",
                r".*\.arlo\.com$",
                r".*\.hikvision\.com$"
            ],
            rate_limits=RateLimit(
                max_connections_per_second=10,
                max_bandwidth_mbps=5,
                max_dns_queries_per_minute=20
            ),
            allow_iot_lateral=False,  # BLOCK IoT-to-IoT
            allow_internet=True,
            allow_lan=False,  # No LAN access except cloud
            require_cloud_only=True,
            behavioral_constraints={
                "max_unique_destinations": 5,  # Should only talk to a few cloud servers
                "allowed_hours": "all",
                "max_protocols": 2  # HTTPS + DNS/NTP only
            }
        )

        # ==================== SMART PLUGS ====================
        self.policies["smart_plug"] = DevicePolicy(
            device_type="smart_plug",
            allowed_zones=["iot"],
            permitted_protocols=["tcp", "udp"],
            permitted_ports=[
                PortRule("tcp", 443, "outbound", "HTTPS to cloud"),
                PortRule("tcp", 8883, "outbound", "MQTT over TLS"),
                PortRule("udp", 53, "outbound", "DNS"),
                PortRule("udp", 123, "outbound", "NTP"),
            ],
            dns_whitelist_patterns=[
                r".*\.tplinkcloud\.com$",
                r".*\.tuya\.com$",
                r".*\.kasaapi\.com$",
                r".*\.smartthings\.com$"
            ],
            rate_limits=RateLimit(
                max_connections_per_second=5,
                max_bandwidth_mbps=1,
                max_dns_queries_per_minute=10
            ),
            allow_iot_lateral=False,
            allow_internet=True,
            allow_lan=False,
            require_cloud_only=True,
            behavioral_constraints={
                "max_unique_destinations": 3,
                "allowed_hours": "all",
                "max_protocols": 2
            }
        )

        # ==================== SMART SPEAKERS ====================
        self.policies["smart_speaker"] = DevicePolicy(
            device_type="smart_speaker",
            allowed_zones=["iot"],
            permitted_protocols=["tcp", "udp"],
            permitted_ports=[
                PortRule("tcp", 443, "outbound", "HTTPS"),
                PortRule("tcp", 4070, "outbound", "Alexa voice"),
                PortRule("udp", 53, "outbound", "DNS"),
                PortRule("udp", 123, "outbound", "NTP"),
                PortRule("tcp", 5353, "both", "mDNS discovery"),
            ],
            dns_whitelist_patterns=[
                r".*\.amazon\.com$",
                r".*\.googleapis\.com$",
                r".*\.google\.com$",
                r".*\.alexa\.com$",
                r".*\.cloudfront\.net$"
            ],
            rate_limits=RateLimit(
                max_connections_per_second=20,
                max_bandwidth_mbps=10,
                max_dns_queries_per_minute=50
            ),
            allow_iot_lateral=False,
            allow_internet=True,
            allow_lan=True,  # Needs LAN for Chromecast/streaming
            require_cloud_only=False,
            behavioral_constraints={
                "max_unique_destinations": 20,
                "allowed_hours": "all",
                "max_protocols": 3
            }
        )

        # ==================== SMART BULBS ====================
        self.policies["smart_bulb"] = DevicePolicy(
            device_type="smart_bulb",
            allowed_zones=["iot"],
            permitted_protocols=["tcp", "udp"],
            permitted_ports=[
                PortRule("tcp", 443, "outbound", "HTTPS"),
                PortRule("udp", 53, "outbound", "DNS"),
                PortRule("udp", 123, "outbound", "NTP"),
            ],
            dns_whitelist_patterns=[
                r".*\.meethue\.com$",
                r".*\.philips-hue\.com$",
                r".*\.tuya\.com$"
            ],
            rate_limits=RateLimit(
                max_connections_per_second=5,
                max_bandwidth_mbps=1,
                max_dns_queries_per_minute=10
            ),
            allow_iot_lateral=False,
            allow_internet=True,
            allow_lan=False,
            require_cloud_only=True,
            behavioral_constraints={
                "max_unique_destinations": 2,
                "allowed_hours": "all",
                "max_protocols": 1
            }
        )

        # ==================== LAPTOPS/DESKTOPS ====================
        self.policies["laptop"] = DevicePolicy(
            device_type="laptop",
            allowed_zones=["main"],
            permitted_protocols=["tcp", "udp", "icmp"],
            permitted_ports=[
                PortRule("tcp", 0, "both", "All TCP ports"),
                PortRule("udp", 0, "both", "All UDP ports"),
                PortRule("icmp", 0, "both", "ICMP"),
            ],
            dns_whitelist_patterns=[],  # No DNS restrictions for laptops
            rate_limits=RateLimit(
                max_connections_per_second=200,
                max_bandwidth_mbps=100,
                max_dns_queries_per_minute=200
            ),
            allow_iot_lateral=False,  # Even laptops shouldn't talk to IoT directly
            allow_internet=True,
            allow_lan=True,
            require_cloud_only=False,
            behavioral_constraints={
                "max_unique_destinations": 1000,
                "allowed_hours": "all",
                "max_protocols": 10
            }
        )

        # ==================== MOBILE DEVICES ====================
        self.policies["mobile"] = DevicePolicy(
            device_type="mobile",
            allowed_zones=["main"],
            permitted_protocols=["tcp", "udp", "icmp"],
            permitted_ports=[
                PortRule("tcp", 0, "both", "All TCP"),
                PortRule("udp", 0, "both", "All UDP"),
            ],
            dns_whitelist_patterns=[],
            rate_limits=RateLimit(
                max_connections_per_second=100,
                max_bandwidth_mbps=50,
                max_dns_queries_per_minute=100
            ),
            allow_iot_lateral=False,
            allow_internet=True,
            allow_lan=True,
            require_cloud_only=False,
            behavioral_constraints={
                "max_unique_destinations": 500,
                "allowed_hours": "all",
                "max_protocols": 8
            }
        )

        # ==================== UNKNOWN DEVICES ====================
        self.policies["unknown"] = DevicePolicy(
            device_type="unknown",
            allowed_zones=["guest"],
            permitted_protocols=["tcp", "udp"],
            permitted_ports=[
                PortRule("tcp", 80, "outbound", "HTTP"),
                PortRule("tcp", 443, "outbound", "HTTPS"),
                PortRule("udp", 53, "outbound", "DNS"),
            ],
            dns_whitelist_patterns=[],
            rate_limits=RateLimit(
                max_connections_per_second=10,
                max_bandwidth_mbps=5,
                max_dns_queries_per_minute=20
            ),
            allow_iot_lateral=False,
            allow_internet=True,
            allow_lan=False,
            require_cloud_only=False,
            behavioral_constraints={
                "max_unique_destinations": 10,
                "allowed_hours": "all",
                "max_protocols": 2
            }
        )

        # Add aliases for common device types
        self.policies["desktop"] = self.policies["laptop"]
        self.policies["workstation"] = self.policies["laptop"]
        self.policies["phone"] = self.policies["mobile"]
        self.policies["tablet"] = self.policies["mobile"]
        self.policies["smartphone"] = self.policies["mobile"]
        self.policies["iphone"] = self.policies["mobile"]
        self.policies["android"] = self.policies["mobile"]

        self.policies["smart_plug"] = self.policies["smart_plug"]
        self.policies["smart_switch"] = self.policies["smart_plug"]
        self.policies["smart_tv"] = self.policies["smart_speaker"]  # Similar requirements
        self.policies["doorbell"] = self.policies["camera"]
        self.policies["nvr"] = self.policies["camera"]
        self.policies["dvr"] = self.policies["camera"]

    def _load_config_policies(self, policy_config: dict):
        """Load custom policies from configuration."""
        # TODO: Implement config-based policy loading
        pass

    def get_policy(self, device_type: str) -> DevicePolicy:
        """
        Get security policy for a device type.

        Args:
            device_type: Device type string

        Returns:
            DevicePolicy object (defaults to "unknown" policy if not found)
        """
        device_type_lower = device_type.lower() if device_type else "unknown"

        # Try exact match
        if device_type_lower in self.policies:
            return self.policies[device_type_lower]

        # Try partial match (e.g., "Wyze Cam" → "camera")
        for policy_type, policy in self.policies.items():
            if policy_type in device_type_lower:
                logger.debug(f"Matched device type '{device_type}' to policy '{policy_type}'")
                return policy

        # Default to unknown policy
        logger.warning(f"No policy found for device type '{device_type}', using 'unknown' policy")
        return self.policies["unknown"]

    def check_port_allowed(
        self,
        device_type: str,
        protocol: str,
        port: int,
        direction: str = "outbound"
    ) -> bool:
        """
        Check if a port is allowed for device type.

        Args:
            device_type: Device type
            protocol: Protocol (tcp, udp, icmp)
            port: Port number
            direction: Traffic direction (outbound, inbound, both)

        Returns:
            True if port is allowed
        """
        policy = self.get_policy(device_type)

        # Check if protocol is permitted
        if protocol.lower() not in [p.lower() for p in policy.permitted_protocols]:
            return False

        # Check port rules
        for port_rule in policy.permitted_ports:
            if port_rule.protocol.lower() != protocol.lower():
                continue

            # Port 0 means any port
            if port_rule.port == 0:
                return True

            # Exact port match
            if port_rule.port == port:
                # Check direction
                if port_rule.direction == "both":
                    return True
                if port_rule.direction == direction:
                    return True

        return False

    def check_dns_allowed(self, device_type: str, domain: str) -> bool:
        """
        Check if DNS query is allowed for device type.

        Args:
            device_type: Device type
            domain: Domain name

        Returns:
            True if domain is allowed
        """
        import fnmatch

        policy = self.get_policy(device_type)

        # No whitelist = allow all
        if not policy.dns_whitelist_patterns:
            return True

        # Check against whitelist patterns
        domain_lower = domain.lower()
        for pattern in policy.dns_whitelist_patterns:
            if fnmatch.fnmatch(domain_lower, pattern.lower()):
                return True

        return False

    def check_rate_limit(
        self,
        device_type: str,
        metric: str,
        current_value: int
    ) -> bool:
        """
        Check if device is within rate limits.

        Args:
            device_type: Device type
            metric: Metric name (connections, bandwidth, dns_queries)
            current_value: Current value

        Returns:
            True if within limits
        """
        policy = self.get_policy(device_type)

        if not policy.rate_limits:
            return True

        if metric == "connections":
            return current_value <= policy.rate_limits.max_connections_per_second
        elif metric == "bandwidth":
            return current_value <= policy.rate_limits.max_bandwidth_mbps
        elif metric == "dns_queries":
            return current_value <= policy.rate_limits.max_dns_queries_per_minute

        return True

    def is_iot_lateral_allowed(self, device_type: str) -> bool:
        """
        Check if IoT-to-IoT lateral movement is allowed.

        CRITICAL: This should be False for all IoT devices to prevent lateral movement.

        Args:
            device_type: Device type

        Returns:
            True if lateral movement allowed (should be False for IoT)
        """
        policy = self.get_policy(device_type)
        return policy.allow_iot_lateral

    def get_allowed_zones(self, device_type: str) -> List[str]:
        """
        Get allowed zones for device type.

        Args:
            device_type: Device type

        Returns:
            List of allowed zone names
        """
        policy = self.get_policy(device_type)
        return policy.allowed_zones

    def get_behavioral_constraint(self, device_type: str, constraint: str) -> any:
        """
        Get behavioral constraint value for device type.

        Args:
            device_type: Device type
            constraint: Constraint name

        Returns:
            Constraint value or None
        """
        policy = self.get_policy(device_type)
        return policy.behavioral_constraints.get(constraint)

    def list_policies(self) -> List[str]:
        """Get list of all policy names."""
        return list(self.policies.keys())
