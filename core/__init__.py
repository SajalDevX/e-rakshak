"""
RAKSHAK Core Modules
====================

India's First Agentic AI Cyber Guardian for Home IoT

Modules:
- network_scanner: MAYA - Device discovery and fingerprinting
- agentic_defender: KAAL - Dueling DQN autonomous agent
- llm_honeypot: PRAHARI - LLM-powered honeypot responses
- deception_engine: CHAKRAVYUH - Multi-layer deception
- threat_logger: Event logging and CCTNS export
- gateway: Inline security gateway (NAT, DHCP, routing)
- packet_filter: Traffic control and deep packet inspection
"""

from .threat_logger import ThreatLogger, SimulatedThreatGenerator
from .network_scanner import NetworkScanner, Device
from .agentic_defender import AgenticDefender
from .llm_honeypot import LLMHoneypot, DevicePersona
from .deception_engine import DeceptionEngine, Honeypot

# DuelingDQN is only available when PyTorch is installed
try:
    from .agentic_defender import DuelingDQN
except (ImportError, TypeError):
    DuelingDQN = None

# Gateway module (requires root privileges for full functionality)
try:
    from .gateway import RakshakGateway, GatewayConfig, create_gateway_from_config
except ImportError:
    RakshakGateway = None
    GatewayConfig = None
    create_gateway_from_config = None

# Packet filter module
try:
    from .packet_filter import PacketFilter, FirewallRule, TrafficAction
except ImportError:
    PacketFilter = None
    FirewallRule = None
    TrafficAction = None

__all__ = [
    # Core modules
    "ThreatLogger",
    "SimulatedThreatGenerator",
    "NetworkScanner",
    "Device",
    "AgenticDefender",
    "DuelingDQN",
    "LLMHoneypot",
    "DevicePersona",
    "DeceptionEngine",
    "Honeypot",
    # Gateway modules
    "RakshakGateway",
    "GatewayConfig",
    "create_gateway_from_config",
    # Packet filter modules
    "PacketFilter",
    "FirewallRule",
    "TrafficAction"
]

__version__ = "1.0.0"
