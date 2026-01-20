#!/usr/bin/env python3
"""
RAKSHAK - India's First Agentic AI Cyber Guardian for Home IoT
===============================================================

Main entry point for the RAKSHAK system.

INLINE SECURITY GATEWAY MODE (DEFAULT):
  RAKSHAK operates as the network gateway between your modem and router.
  This provides full traffic control including:
  - Real device isolation via iptables
  - Traffic blocking and rate limiting
  - Honeypot redirection via NAT
  - Deep packet inspection

Network Topology:
  Internet -> Modem -> [RAKSHAK/Jetson] -> Router (AP mode) -> IoT Devices

STANDALONE MODE (--standalone):
  Legacy passive monitoring mode. For testing only.
  Does NOT provide real traffic control.

Features:
- MAYA: Network scanning and device discovery
- KAAL: Agentic AI defender using Dueling DQN
- PRAHARI: LLM-powered honeypot responses
- CHAKRAVYUH: Multi-layer deception engine
- DRISHTI: Real-time dashboard

Usage:
    sudo python main.py              # Start in gateway mode (default)
    python main.py --standalone      # Run in standalone mode (limited)
    python main.py --simulate        # Run in simulation mode
    python main.py --debug           # Enable debug logging

Author: Team RAKSHAK
License: MIT
"""

import os
import sys
import signal
import platform
import subprocess
import json
import threading
from pathlib import Path
from typing import Tuple, List

import yaml
import click
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import RAKSHAK modules
from core.network_scanner import NetworkScanner
from core.agentic_defender import AgenticDefender
from core.llm_honeypot import LLMHoneypot
from core.deception_engine import DeceptionEngine
from core.threat_logger import ThreatLogger
from core.ids_classifier import IDSClassifier
from api.app import create_app

# Phase 3: Enhanced Detection & Response Systems
from core.response_decision_engine import ResponseDecisionEngine, ThreatContext
from core.arp_spoofing_detector import ARPSpoofingDetector
from core.port_scan_detector import PortScanDetector
from core.connection_monitor import ConnectionMonitor

# Gateway modules (for inline security gateway mode)
try:
    from core.gateway import RakshakGateway, GatewayConfig, create_gateway_from_config, IsolationLevel
    from core.packet_filter import PacketFilter
    GATEWAY_AVAILABLE = True
except ImportError as e:
    GATEWAY_AVAILABLE = False
    logger.warning(f"Gateway modules not available: {e}")

# ARP Interceptor for LAN-to-LAN protection (KAVACH)
try:
    from core.arp_interceptor import ARPInterceptor, create_interceptor_from_config
    ARP_INTERCEPTOR_AVAILABLE = True
except ImportError as e:
    ARP_INTERCEPTOR_AVAILABLE = False
    logger.warning(f"ARP interceptor not available: {e}")

# Rich console for pretty output
console = Console()


def load_config(config_path: str = "config/config.yaml") -> dict:
    """Load configuration from YAML file."""
    config_file = PROJECT_ROOT / config_path
    if not config_file.exists():
        logger.error(f"Config file not found: {config_file}")
        sys.exit(1)

    with open(config_file, "r") as f:
        config = yaml.safe_load(f)

    return config


def setup_logging(config: dict) -> None:
    """Configure logging based on config."""
    log_config = config.get("logging", {})
    log_level = config.get("general", {}).get("log_level", "INFO")
    log_file = PROJECT_ROOT / log_config.get("file", "data/logs/rakshak.log")

    # Ensure log directory exists
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Remove default logger and add custom configuration
    logger.remove()
    logger.add(
        sys.stderr,
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan> | <level>{message}</level>"
    )
    logger.add(
        str(log_file),
        level=log_level,
        rotation=log_config.get("max_size", "10 MB"),
        retention=log_config.get("backup_count", 5),
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name} | {message}"
    )


def print_banner():
    """Print RAKSHAK ASCII banner."""
    banner = """
    ██████╗  █████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗  ██╗
    ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║ ██╔╝
    ██████╔╝███████║█████╔╝ ███████╗███████║███████║█████╔╝
    ██╔══██╗██╔══██║██╔═██╗ ╚════██║██╔══██║██╔══██║██╔═██╗
    ██║  ██║██║  ██║██║  ██╗███████║██║  ██║██║  ██║██║  ██╗
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
                    रक्षक - Cyber Guardian
    """

    console.print(Panel(
        Text(banner, style="bold cyan"),
        title="[bold white]India's First Agentic AI Cyber Guardian for Home IoT[/bold white]",
        subtitle="[dim]Har Ghar Ki Cyber Suraksha[/dim]",
        border_style="cyan"
    ))


def check_gateway_prerequisites() -> Tuple[bool, List[str]]:
    """
    Check if system meets gateway requirements.
    Returns (success, list_of_issues).
    """
    issues = []

    # 1. Check root privileges
    if os.geteuid() != 0:
        issues.append("Must run as root (sudo python main.py)")

    # 2. Detect platform
    is_jetson = os.path.exists("/etc/nv_tegra_release")
    if is_jetson:
        logger.info("Jetson platform detected")

    # 3. Check for required tools
    required_tools = ["iptables", "dnsmasq", "ip", "sysctl"]
    for tool in required_tools:
        result = subprocess.run(["which", tool], capture_output=True)
        if result.returncode != 0:
            issues.append(f"Missing required tool: {tool}")

    # 4. Check for two network interfaces
    try:
        result = subprocess.run(
            ["ip", "-j", "link", "show"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            links = json.loads(result.stdout)

            # Filter to ethernet interfaces (not lo, docker, veth, etc.)
            eth_interfaces = []
            for link in links:
                name = link.get("ifname", "")
                if name.startswith(("eth", "enp", "enx", "ens")) and name != "lo":
                    eth_interfaces.append(name)

            if len(eth_interfaces) < 2:
                issues.append(f"Need 2 ethernet interfaces, found: {eth_interfaces}")
                issues.append("Connect a USB-to-Ethernet adapter for the second interface")
    except Exception as e:
        issues.append(f"Failed to detect network interfaces: {e}")

    # 5. Check IP forwarding capability
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            current = f.read().strip()
            logger.debug(f"Current IP forwarding: {current}")
    except Exception as e:
        issues.append(f"Cannot check IP forwarding: {e}")

    return len(issues) == 0, issues


def detect_network_interfaces() -> Tuple[str, str]:
    """
    Auto-detect WAN and LAN interfaces.
    Returns (wan_interface, lan_interface).
    """
    try:
        result = subprocess.run(
            ["ip", "-j", "link", "show"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return None, None

        links = json.loads(result.stdout)

        interfaces = []
        for link in links:
            name = link.get("ifname", "")
            if name.startswith(("eth", "enp", "enx", "ens")) and name != "lo":
                interfaces.append(name)

        if len(interfaces) >= 2:
            # Assume eth0 is WAN (built-in), eth1/enx* is LAN (USB)
            wan = "eth0" if "eth0" in interfaces else interfaces[0]
            lan = [i for i in interfaces if i != wan][0]
            return wan, lan
        elif len(interfaces) == 1:
            return interfaces[0], None
        else:
            return None, None

    except Exception as e:
        logger.error(f"Failed to detect interfaces: {e}")
        return None, None


class RakshakOrchestrator:
    """
    Main orchestrator that coordinates all RAKSHAK components.

    In GATEWAY MODE (default):
    - Gateway is mandatory and initialized first
    - All traffic flows through Jetson
    - Real device isolation via iptables
    - Real honeypot redirection via NAT

    In STANDALONE MODE:
    - Gateway is not used
    - Passive monitoring only
    - Actions are logged but not enforced

    Components:
    - NetworkScanner (MAYA): Device discovery and monitoring
    - AgenticDefender (KAAL): RL-based autonomous decisions
    - LLMHoneypot (PRAHARI): Dynamic response generation
    - DeceptionEngine (CHAKRAVYUH): Honeypot deployment
    - ThreatLogger: Event logging and export
    - RakshakGateway: Inline security gateway
    - PacketFilter: Traffic control and inspection
    """

    def __init__(self, config: dict, gateway_mode: bool = True):
        self.config = config
        self.running = False
        self.simulation_mode = config.get("simulation", {}).get("enabled", False)
        self.gateway_mode = gateway_mode

        logger.info("Initializing RAKSHAK components...")

        # Initialize gateway FIRST if in gateway mode
        self.gateway = None
        self.packet_filter = None
        self.arp_interceptor = None  # KAVACH for LAN-to-LAN protection

        if gateway_mode:
            if not GATEWAY_AVAILABLE:
                logger.error("Gateway modules not available! Install: pip install netfilterqueue")
                raise RuntimeError("Gateway modules required but not available")

            self._init_gateway_mode()

        # Initialize other components
        self.threat_logger = ThreatLogger(config)
        self.llm_honeypot = LLMHoneypot(config)

        # Initialize Trust Manager for Zero Trust enrollment
        self.trust_manager = None
        if gateway_mode and self.gateway:
            try:
                from core.trust_manager import TrustManager
                db_path = config.get("database", {}).get("path", "data/rakshak.db")

                self.trust_manager = TrustManager(
                    config=config,
                    db_path=db_path,
                    gateway=self.gateway
                )
                logger.info("Trust Manager initialized for Zero Trust enrollment")
            except Exception as e:
                logger.warning(f"Failed to initialize Trust Manager: {e}")
                self.trust_manager = None

        # Initialize IDS classifier
        self.ids_classifier = IDSClassifier(model_dir="models/ids")
        if self.ids_classifier.is_loaded:
            logger.info("IDS classifier loaded successfully")
        else:
            logger.warning("IDS classifier not loaded - using rule-based detection only")

        # Initialize Phase 3: Enhanced Detection & Response Systems
        self.response_engine = ResponseDecisionEngine(config)
        self.arp_spoofing_detector = ARPSpoofingDetector(config, self.threat_logger)
        self.port_scan_detector = PortScanDetector(config, self.threat_logger)
        self.connection_monitor = None  # Will be initialized in gateway mode
        logger.info("Phase 3 detection systems initialized (Response Engine, ARP Spoofing, Port Scan)")

        # Pass gateway reference to components that need it
        self.network_scanner = NetworkScanner(
            config,
            self.threat_logger,
            gateway=self.gateway,
            trust_manager=self.trust_manager,
            orchestrator=self
        )
        self.deception_engine = DeceptionEngine(
            config,
            self.llm_honeypot,
            self.threat_logger,
            gateway=self.gateway
        )
        self.agentic_defender = AgenticDefender(config, self.threat_logger)

        # Connect gateway to agentic defender
        if self.gateway:
            self.agentic_defender.set_gateway(self.gateway)
        if self.packet_filter:
            self.agentic_defender.set_packet_filter(self.packet_filter)
            # Connect IDS classifier callback to packet filter
            self.packet_filter.on_threat_detected = self._on_packet_inspected
            # Connect dashboard access callback
            self.packet_filter.on_dashboard_access = self._on_dashboard_access
            # Set gateway IP for dashboard monitoring
            lan_ip = self.config.get("gateway", {}).get("lan_ip", "10.42.0.1")
            self.packet_filter.gateway_ip = lan_ip

            # Phase 3: Connect enhanced detectors to packet filter
            self.packet_filter.port_scan_detector = self.port_scan_detector
            self.packet_filter.arp_spoofing_detector = self.arp_spoofing_detector
            logger.info("Phase 3 detectors connected to packet filter")

        # Flask app for dashboard
        self.app = create_app(config, self)

        # Import and assign socketio immediately (before threads start)
        # This fixes the race condition where threat processor starts before socketio is available
        from api.app import socketio
        self.socketio = socketio

        logger.info("RAKSHAK components initialized successfully")

    def _init_gateway_mode(self):
        """Initialize gateway mode components."""
        logger.info("Initializing GATEWAY MODE...")

        try:
            # Create gateway from config
            self.gateway = create_gateway_from_config(self.config)

            # Create packet filter
            lan_interface = self.config.get("gateway", {}).get("lan_interface", "eth1")
            self.packet_filter = PacketFilter(lan_interface=lan_interface)

            # Set target MAC from config for auto-isolation
            auto_isolation_config = self.config.get("gateway", {}).get("auto_isolation", {})
            if auto_isolation_config.get("enabled", True):
                target_macs = auto_isolation_config.get("target_macs", ["C4:D8:D5:03:8E:7F"])
                if target_macs:
                    self.packet_filter.target_mac_for_isolation = target_macs[0].upper()
                    logger.info(f"Auto-isolation enabled for MAC: {self.packet_filter.target_mac_for_isolation}")
            else:
                self.packet_filter.target_mac_for_isolation = None
                logger.info("Auto-isolation disabled in config")

            logger.info("Gateway mode components initialized")

        except Exception as e:
            logger.error(f"Failed to initialize gateway mode: {e}")
            raise

    def start(self):
        """Start all RAKSHAK components."""
        self.running = True

        mode = "SIMULATION" if self.simulation_mode else "LIVE"
        if self.gateway_mode:
            mode = "GATEWAY"

        logger.info(f"Starting RAKSHAK in {mode} mode...")

        # Start gateway if in gateway mode
        if self.gateway_mode and self.gateway:
            logger.info("Starting gateway...")
            if not self.gateway.start_gateway():
                logger.error("Failed to start gateway!")
                console.print("[bold red]ERROR: Failed to start gateway mode![/bold red]")
                console.print("[dim]Check prerequisites with: sudo ./scripts/setup_gateway.sh --check[/dim]")
                raise RuntimeError("Gateway startup failed")

            console.print("\n[bold cyan]" + "=" * 60 + "[/bold cyan]")
            console.print("[bold cyan]       RAKSHAK GATEWAY MODE ACTIVE[/bold cyan]")
            console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]\n")
            console.print(f"  WAN Interface: {self.gateway.config.wan_interface}")
            console.print(f"  LAN Interface: {self.gateway.config.lan_interface}")
            if self.gateway.config.bridge_mode:
                console.print(f"  Bridge Mode:   ENABLED ({self.gateway.config.bridge_name})")
            console.print(f"  Gateway IP:    {self.gateway.config.lan_ip}")
            console.print(f"  Jetson:        {self.gateway.is_jetson}")
            console.print("")

            # Start dashboard access monitor
            if self.packet_filter:
                self.packet_filter.is_running = True
                self.packet_filter.start_dashboard_monitor()
                console.print("[dim]Dashboard access monitoring enabled[/dim]")

                # Start packet inspection for threat detection
                try:
                    self.packet_filter.start_packet_inspection(queue_num=1)
                    console.print("[bold cyan]Packet inspection started (Port Scan & Threat Detection)[/bold cyan]")
                except Exception as e:
                    logger.warning(f"Could not start packet inspection (nfqueue unavailable): {e}")

                    # Fallback: Use connection monitor (iptables LOG based detection)
                    console.print(f"[cyan]Starting alternative connection monitor (iptables LOG based)[/cyan]")
                    try:
                        self.connection_monitor = ConnectionMonitor(
                            interface=self.config.get("gateway", {}).get("bridge", {}).get("name", "br0"),
                            callback=self._on_port_scan_detected
                        )
                        self.connection_monitor.start()
                        console.print("[bold green]✓ Connection monitor started (Port Scan Detection)[/bold green]")
                    except Exception as conn_err:
                        logger.error(f"Connection monitor also failed: {conn_err}")
                        console.print(f"[red]⚠️  Port scan detection unavailable[/red]")

            # Deploy startup trap honeypots for proactive defense
            if self.deception_engine.enabled:
                self._deploy_startup_honeypots()

            # Start KAVACH (ARP Interceptor) for LAN-to-LAN protection
            if ARP_INTERCEPTOR_AVAILABLE:
                self._start_arp_interceptor()

            # Start passive discovery for static IP devices (cameras, NVRs)
            if self.network_scanner.passive_discovery:
                self.network_scanner.start_passive_discovery()
                console.print("[bold cyan]MAYA: Passive discovery active (SSDP, ONVIF, ARP)[/bold cyan]")

        console.print(f"[bold green]RAKSHAK Started in {mode} mode[/bold green]")
        console.print(f"[dim]Dashboard: http://localhost:{self.config['api']['port']}[/dim]\n")

        # Start components in threads
        threads = []

        # Network scanner thread
        scanner_thread = threading.Thread(
            target=self._run_scanner_loop,
            daemon=True,
            name="NetworkScanner"
        )
        threads.append(scanner_thread)

        # Threat processor thread
        processor_thread = threading.Thread(
            target=self._run_threat_processor,
            daemon=True,
            name="ThreatProcessor"
        )
        threads.append(processor_thread)

        # Start all threads
        for thread in threads:
            thread.start()
            logger.debug(f"Started thread: {thread.name}")

        # Run Flask app in main thread
        self._run_flask_app()

    def stop(self):
        """Stop all RAKSHAK components."""
        logger.info("Stopping RAKSHAK...")
        self.running = False
        self.deception_engine.stop_all_honeypots()

        # Stop connection monitor if active
        if self.connection_monitor:
            logger.info("Stopping connection monitor...")
            self.connection_monitor.stop()

        # Stop passive discovery if active
        if self.network_scanner.passive_discovery:
            logger.info("Stopping MAYA passive discovery...")
            self.network_scanner.stop_passive_discovery()

        # Stop ARP interceptor if active (restores ARP tables)
        if self.arp_interceptor:
            logger.info("Stopping KAVACH ARP interceptor...")
            self.arp_interceptor.stop()

        # Stop gateway if active
        if self.gateway_mode and self.gateway:
            logger.info("Stopping gateway...")
            self.gateway.stop_gateway()

        # Stop packet filter if active
        if self.packet_filter:
            self.packet_filter.stop()

        logger.info("RAKSHAK stopped")

    def _run_scanner_loop(self):
        """Background loop for network scanning."""
        scan_interval = self.config.get("network", {}).get("scan_interval", 60)

        while self.running:
            try:
                if self.simulation_mode:
                    devices = self.network_scanner.get_simulated_devices()
                elif self.gateway_mode and self.gateway:
                    # In gateway mode, use DHCP leases for device discovery
                    devices = self.network_scanner.discover_devices_from_dhcp()
                else:
                    devices = self.network_scanner.discover_devices()

                logger.debug(f"Discovered {len(devices)} devices")

                # Check for new devices or changes
                for device in devices:
                    self.network_scanner.update_device(device)

                # Emit devices_update event to dashboard
                self._emit_event('devices_update', {
                    'devices': [d.to_dict() for d in devices],
                    'count': len(devices)
                })

                # Update known devices list for dashboard access monitoring
                if self.packet_filter and devices:
                    known_ips = [d.ip for d in devices if d.status == "active"]
                    self.packet_filter.set_known_devices(known_ips)

                # Update KAVACH ARP interceptor with discovered devices
                if self.arp_interceptor and devices:
                    for device in devices:
                        if device.status == "active" and device.mac:
                            self.arp_interceptor.add_device(device.ip, device.mac)

                # Cleanup stale inactive devices (removes after 2 hours of inactivity)
                # Increased from 5 minutes to prevent removal of idle/sleeping devices
                self.network_scanner.cleanup_stale_devices(inactive_threshold_seconds=7200)

            except Exception as e:
                logger.error(f"Scanner error: {e}")

            # Wait for next scan
            for _ in range(scan_interval):
                if not self.running:
                    break
                import time
                time.sleep(1)

    def _run_threat_processor(self):
        """Background loop for processing threats."""
        while self.running:
            try:
                # Get pending threats from logger
                threat = self.threat_logger.get_next_threat()

                if threat:
                    self._process_threat(threat)
                else:
                    import time
                    time.sleep(0.5)

            except Exception as e:
                logger.error(f"Threat processor error: {e}")

    def _process_threat(self, threat: dict):
        """Process a detected threat using the agentic defender and response engine."""
        logger.info(f"Processing threat: {threat.get('type')} from {threat.get('source_ip')}")

        # Emit threat_detected event to dashboard
        self._emit_event('threat_detected', {
            'threat': threat,
            'message': f"Threat detected: {threat.get('type')} from {threat.get('source_ip')}"
        })

        # Phase 3: Use Response Decision Engine for graduated response
        response_decision = None
        if self.response_engine:
            # Build threat context for response engine
            from core.response_decision_engine import ThreatContext

            # Get device info
            source_device = self.network_scanner.get_device(threat.get('source_ip'))
            device_zone = source_device.zone if source_device else "guest"
            device_type = source_device.device_type if source_device else "unknown"
            device_criticality = self._get_device_criticality(device_type)

            # Check if repeat offender
            is_repeat = self.response_engine.check_repeat_offender(threat.get('source_ip'))

            context = ThreatContext(
                threat_type=threat.get('type', 'unknown'),
                severity=threat.get('severity', 'medium'),
                confidence=threat.get('confidence', 0.7),
                source_ip=threat.get('source_ip'),
                device_type=device_type,
                device_zone=device_zone,
                device_criticality=device_criticality,
                anomaly_count=threat.get('anomaly_count', 0),
                is_repeat_offender=is_repeat
            )

            response_decision = self.response_engine.decide_response(context)
            logger.info(f"Response Engine: {response_decision.level.name} - {response_decision.action}")

        # Get AI decision from KAAL
        action = self.agentic_defender.decide(threat)
        logger.info(f"KAAL decided: {action['action']}")

        # If response engine provided higher escalation, use it
        if response_decision and response_decision.auto_execute:
            logger.warning(f"Response Engine escalating to: {response_decision.level.name}")
            # Map response level to action
            action = self._map_response_to_action(response_decision, threat)

        # Execute action
        self._execute_action(action, threat)

        # Log the decision
        self.threat_logger.log_decision(threat, action)

        # Emit action_taken event
        self._emit_event('action_taken', {
            'action': action['action'],
            'threat_type': threat.get('type'),
            'target': threat.get('target_device'),
            'message': f"KAAL action: {action['action']}",
            'gateway_mode': self.gateway_mode,
            'response_level': response_decision.level.name if response_decision else None
        })

        # Emit status update
        self._emit_event('status_update', self.get_status())

    def _execute_action(self, action: dict, threat: dict):
        """Execute the action decided by KAAL."""
        action_type = action.get("action")

        # Use the integrated execute_action method from agentic_defender
        # This provides real traffic control when in gateway mode
        result = self.agentic_defender.execute_action(
            decision=action,
            threat_info=threat,
            deception_engine=self.deception_engine
        )

        # Log whether real action was taken
        if result.get('real_action_taken'):
            logger.warning(f"REAL ACTION TAKEN: {action_type}")
        else:
            logger.info(f"Action logged (no gateway): {action_type}")

        # Emit events based on action type
        if action_type == "MONITOR":
            logger.debug("Action: Continue monitoring")

        elif action_type == "DEPLOY_HONEYPOT":
            logger.info("Action: Deploying honeypot")
            if result.get("honeypot_id"):
                self._emit_event('honeypot_deployed', {
                    'honeypot_id': result.get('honeypot_id'),
                    'message': result.get('message', 'Honeypot deployed'),
                    'real_action': result.get('real_action_taken', False)
                })

        elif action_type == "ISOLATE_DEVICE":
            logger.warning(f"Action: Isolating device {threat.get('target_device')}")
            self._emit_event('device_isolated', {
                'device': threat.get('target_device'),
                'ip': threat.get('source_ip'),
                'message': result.get('message', 'Device isolated'),
                'real_action': result.get('real_action_taken', False)
            })

        elif action_type == "ENGAGE_ATTACKER":
            logger.info("Action: Engaging attacker with honeypot")
            self._emit_event('attacker_engaged', {
                'target': threat.get('source_ip'),
                'message': result.get('message', 'Attacker engaged'),
                'real_action': result.get('real_action_taken', False)
            })

        elif action_type == "ALERT_USER":
            logger.info("Action: Alerting user")
            self._send_alert(threat)

        return result

    def _get_device_criticality(self, device_type: str) -> str:
        """
        Determine device criticality level.

        Returns: "low", "medium", "high", or "critical"
        """
        critical_devices = ["server", "nas", "gateway", "router"]
        high_devices = ["desktop", "laptop", "workstation"]
        medium_devices = ["mobile", "tablet", "smart_tv"]
        # low: IoT devices, cameras, smart plugs, etc.

        if device_type in critical_devices:
            return "critical"
        elif device_type in high_devices:
            return "high"
        elif device_type in medium_devices:
            return "medium"
        else:
            return "low"  # Default for IoT devices

    def _map_response_to_action(self, response_decision, threat: dict) -> dict:
        """
        Map Response Decision Engine output to KAAL action format.

        Args:
            response_decision: ResponseDecision from response engine
            threat: Threat dictionary

        Returns:
            Action dictionary compatible with KAAL
        """
        from core.response_decision_engine import ResponseLevel

        # Map response levels to KAAL actions
        level_to_action = {
            ResponseLevel.MONITOR: "MONITOR",
            ResponseLevel.ALERT: "ALERT_USER",
            ResponseLevel.RATE_LIMIT: "MONITOR",  # Mapped to MONITOR (gateway handles rate limiting)
            ResponseLevel.DEPLOY_HONEYPOT: "DEPLOY_HONEYPOT",
            ResponseLevel.QUARANTINE: "ISOLATE_DEVICE",
            ResponseLevel.ISOLATE: "ISOLATE_DEVICE",
            ResponseLevel.FULL_BLOCK: "ISOLATE_DEVICE"
        }

        kaal_action = level_to_action.get(response_decision.level, "MONITOR")

        return {
            "action": kaal_action,
            "confidence": response_decision.confidence,
            "reason": response_decision.reason,
            "response_level": response_decision.level.name,
            "auto_execute": response_decision.auto_execute,
            "requires_approval": response_decision.requires_approval
        }

    def _emit_event(self, event_name: str, data: dict):
        """Emit a WebSocket event to the dashboard."""
        if hasattr(self, 'socketio') and self.socketio:
            try:
                self.socketio.emit(event_name, data)
            except Exception as e:
                logger.debug(f"Failed to emit {event_name}: {e}")

    def _send_alert(self, threat: dict):
        """Send alert to user via dashboard."""
        lang = self.config.get("general", {}).get("language", "en")
        alerts = self.config.get("alerts", {}).get(lang, {})

        message = alerts.get("threat_detected", "Threat detected!").format(
            device=threat.get("target_device", "unknown device"),
            ip=threat.get("source_ip", "unknown")
        )

        # Emit via WebSocket (handled by Flask-SocketIO)
        if hasattr(self, 'socketio'):
            self.socketio.emit('alert', {
                'message': message,
                'threat': threat,
                'severity': threat.get('severity', 'medium')
            })

        console.print(f"[bold red]ALERT:[/bold red] {message}")

    def _classify_flow(self, flow_data: dict):
        """Classify network flow using IDS and create threat if malicious."""
        if not hasattr(self, 'ids_classifier') or not self.ids_classifier.is_loaded:
            return None

        # Get KAAL-compatible threat info (returns None if BENIGN)
        threat_info = self.ids_classifier.get_threat_info(flow_data)

        if threat_info:
            logger.info(f"IDS detected: {threat_info.get('ids_attack_type')} "
                       f"from {threat_info.get('source_ip')}")

        return threat_info

    def _on_packet_inspected(self, packet_info: dict):
        """Callback when packet filter detects suspicious traffic."""
        # Check if this is a rate-based DDoS detection (bypasses IDS)
        if packet_info.get('reason') == 'high_packet_rate':
            # Rate-based DDoS detection - log directly without IDS
            logger.critical(f"Rate-based DDoS: {packet_info.get('source_ip')} -> {packet_info.get('dest_ip')} "
                          f"({packet_info.get('packet_rate', 0):.1f} pps)")

            threat_info = {
                'type': 'dos_attack',  # KAAL type
                'attack_type': packet_info.get('attack_type', 'ddos'),
                'severity': 'critical',
                'source_ip': packet_info.get('source_ip'),
                'target_ip': packet_info.get('dest_ip'),
                'target_port': packet_info.get('dest_port', 0),
                'protocol': packet_info.get('protocol', 'tcp'),
                'packet_rate': packet_info.get('packet_rate', 0),
                'packets_per_second': packet_info.get('packets_per_second', 0),
                'confidence': 0.95,
                'description': f"High packet rate DDoS detected: {packet_info.get('packet_rate', 0):.1f} packets/s",
                'detected_by': 'rate_detector',
                # Add MAC information
                'source_mac': packet_info.get('source_mac'),
                'is_target_mac': packet_info.get('is_target_mac', False),
                'auto_isolate': packet_info.get('auto_isolate', False)
            }

            # Add device info
            target_ip = threat_info.get('target_ip', '')
            threat_info['target_device'] = self.network_scanner.get_device_name(
                target_ip
            ) if hasattr(self.network_scanner, 'get_device_name') else 'Unknown Device'

            # Log threat directly (bypass IDS) - call with individual arguments
            self.threat_logger.log_threat(
                threat_type=threat_info['type'],
                severity=threat_info['severity'],
                source_ip=threat_info['source_ip'],
                target_ip=threat_info['target_ip'],
                target_device=threat_info['target_device'],
                source_port=threat_info.get('source_port', 0),
                target_port=threat_info.get('target_port', 0),
                protocol=threat_info.get('protocol', 'tcp'),
                payload=threat_info.get('description', ''),
                packets_count=threat_info.get('packets_count', 1),
                duration_seconds=threat_info.get('duration_seconds', 0.0),
                detected_by=threat_info.get('detected_by', 'packet_filter'),
                raw_data=threat_info.get('raw_data', {})
            )

            # If auto-isolate flag is set, skip KAAL and isolate immediately
            if threat_info.get('auto_isolate'):
                # Use the specific target identified by packet filter
                target_ip = threat_info.get('target_ip_to_isolate', threat_info.get('source_ip'))
                target_mac = threat_info.get('target_mac_to_isolate', threat_info.get('source_mac'))
                isolation_reason = threat_info.get('isolation_reason', 'DDoS attack detected')

                logger.critical(f"AUTO-ISOLATION TRIGGERED for {target_ip} (MAC: {target_mac}) - Reason: {isolation_reason}")

                # Immediate isolation without AI evaluation
                if self.gateway:
                    # First, isolate by IP (standard method)
                    self.gateway.isolate_device(
                        ip_address=target_ip,
                        level=IsolationLevel.FULL,
                        reason=f"Auto-isolation: {isolation_reason}",
                        duration_minutes=None  # Permanent
                    )

                    # Also add MAC-based iptables rule for redundancy if MAC is available
                    if target_mac:
                        self.gateway.isolate_device_by_mac(
                            mac_address=target_mac,
                            reason=f"Auto-isolation: {isolation_reason}"
                        )

                    logger.critical(f"Device {target_ip} (MAC: {target_mac}) ISOLATED via fast path")

                    # Emit isolation event
                    self._emit_event('device_isolated', {
                        'device': threat_info.get('target_device', 'Unknown'),
                        'ip': target_ip,
                        'mac': target_mac,
                        'message': f'Auto-isolated: {isolation_reason}',
                        'real_action': True,
                        'auto_isolation': True
                    })

                # Still process through KAAL for logging/learning
                if self.agentic_defender:
                    logger.info("Submitting DDoS threat to KAAL for evaluation (post-isolation)...")
                    self._process_threat(threat_info)

            else:
                # Normal flow: Trigger KAAL AI evaluation
                if self.agentic_defender:
                    logger.info("Submitting DDoS threat to KAAL for evaluation...")
                    self._process_threat(threat_info)

            return

        # Normal flow: use IDS classifier for other detections
        from core.ids_classifier import create_flow_from_packet

        # Convert packet to flow format for IDS classification
        flow_data = create_flow_from_packet(packet_info)

        # Classify using IDS
        threat_info = self._classify_flow(flow_data)

        if threat_info:
            # Add device info if available
            target_ip = threat_info.get('target_ip', '')
            threat_info['target_device'] = self.network_scanner.get_device_name(
                target_ip
            ) if hasattr(self.network_scanner, 'get_device_name') else 'Unknown Device'

            # Queue threat for processing by KAAL
            self.threat_logger.log_threat(threat_info)

    def _on_port_scan_detected(self, scan_info: dict):
        """Callback when connection monitor detects port scanning."""
        source_ip = scan_info.get('source_ip', 'unknown')
        target_ip = scan_info.get('target_ip', 'unknown')
        port_count = scan_info.get('port_count', 0)
        severity = scan_info.get('severity', 'medium')

        logger.warning(f"PORT SCAN DETECTED: {source_ip} -> {target_ip} ({port_count} ports)")

        # Get device name
        device_name = 'Unknown Device'
        if self.network_scanner:
            devices = self.network_scanner.get_all_devices()
            for device in devices:
                if device.ip == source_ip:
                    device_name = device.hostname or f"{device.manufacturer} {device.device_type}"
                    break

        # Create threat info for KAAL to process
        threat_info = {
            'type': 'port_scan',
            'severity': 'high' if port_count > 20 else 'medium',
            'source_ip': source_ip,
            'target_ip': target_ip,
            'target_port': 0,  # Multiple ports
            'target_device': device_name,
            'protocol': 'tcp',
            'packets_count': scan_info.get('connections', port_count),
            'duration_seconds': scan_info.get('time_window', 60),
            'description': f'Port scan detected: {port_count} unique ports scanned',
            'ports_scanned': port_count,
            'attack_type': 'port_scan'
        }

        # Log threat
        if self.threat_logger:
            self.threat_logger.log_threat(threat_info)

        # Trigger agentic defender to decide response
        if self.agentic_defender:
            logger.info(f"Submitting port scan threat to KAAL for evaluation...")
            self._process_threat(threat_info)

    def _on_dashboard_access(self, access_info: dict):
        """Callback when suspicious dashboard access is detected."""
        if not access_info.get('suspicious'):
            return

        source_ip = access_info.get('source_ip', 'unknown')
        reason = access_info.get('reason', 'Suspicious access pattern')

        logger.warning(f"Suspicious dashboard access from {source_ip}: {reason}")

        # Create threat for KAAL to process
        threat_info = {
            'type': 'unauthorized_access',
            'severity': 'medium',
            'source_ip': source_ip,
            'target_ip': access_info.get('target_ip', '10.42.0.1'),
            'target_port': 5000,
            'target_device': 'RAKSHAK Gateway',
            'protocol': 'tcp',
            'packets_count': access_info.get('connection_count', 1),
            'duration_seconds': 10,
            'description': reason,
            'detected_by': 'dashboard_monitor'
        }

        # Log the threat (this will queue it for KAAL processing)
        self.threat_logger.log_threat(
            threat_type=threat_info['type'],
            severity=threat_info['severity'],
            source_ip=threat_info['source_ip'],
            target_ip=threat_info['target_ip'],
            target_device=threat_info['target_device'],
            target_port=threat_info['target_port'],
            protocol=threat_info['protocol'],
            packets_count=threat_info['packets_count'],
            duration_seconds=threat_info['duration_seconds'],
            detected_by=threat_info['detected_by']
        )

        # Emit alert to dashboard
        self._emit_event('alert', {
            'message': f"Suspicious access to dashboard from {source_ip}",
            'severity': 'warning',
            'source_ip': source_ip,
            'reason': reason
        })

    def _deploy_startup_honeypots(self):
        """Deploy honeypots on trap ports at startup for proactive defense."""
        deception_config = self.config.get("deception", {})

        if not deception_config.get("auto_deploy_on_startup", False):
            logger.info("Auto-deploy honeypots disabled in config")
            return

        trap_ports = deception_config.get("trap_ports", [])
        if not trap_ports:
            # Default trap ports if not configured
            trap_ports = [
                {"port": 21, "protocol": "telnet", "persona": "tp_link"},
                {"port": 23, "protocol": "telnet", "persona": "wyze_cam"},
                {"port": 80, "protocol": "http", "persona": "samsung_tv"},
                {"port": 8080, "protocol": "http", "persona": "tp_link"},
                {"port": 22, "protocol": "telnet", "persona": "nest"},
            ]

        deployed_count = 0
        for trap in trap_ports:
            port = trap.get("port")
            protocol = trap.get("protocol", "telnet")
            persona = trap.get("persona", "tp_link")

            # Check if port is available
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", port))
                sock.close()
            except OSError:
                logger.warning(f"Trap port {port} already in use, skipping")
                continue

            # Deploy honeypot on this fixed port
            honeypot = self.deception_engine.deploy_honeypot(
                threat_info={"target_device": persona, "startup_trap": True},
                protocol=protocol,
                persona=persona,
                fixed_port=port
            )

            if honeypot:
                deployed_count += 1
                logger.info(f"TRAP: Deployed {protocol} honeypot on port {port} ({persona})")

        if deployed_count > 0:
            console.print(f"[bold cyan]CHAKRAVYUH: {deployed_count} trap honeypots deployed[/bold cyan]")
        else:
            logger.warning("No trap honeypots could be deployed (ports in use?)")

    def _start_arp_interceptor(self):
        """Start KAVACH (ARP Interceptor) for LAN-to-LAN protection."""
        lan_interception_config = self.config.get("gateway", {}).get("lan_interception", {})

        if not lan_interception_config.get("enabled", False):
            logger.info("KAVACH: LAN interception disabled in config")
            return

        try:
            self.arp_interceptor = create_interceptor_from_config(self.config)

            if self.arp_interceptor:
                # Set callback for internal traffic detection
                self.arp_interceptor.on_internal_traffic = self._on_internal_traffic

                # Start the interceptor
                if self.arp_interceptor.start():
                    console.print("[bold cyan]KAVACH: LAN-to-LAN interception active[/bold cyan]")
                    console.print("[dim]All internal traffic now flows through RAKSHAK[/dim]")
                else:
                    logger.error("KAVACH: Failed to start ARP interceptor")
            else:
                logger.warning("KAVACH: Could not create ARP interceptor")

        except Exception as e:
            logger.error(f"KAVACH: Error starting ARP interceptor: {e}")

    def _on_internal_traffic(self, traffic_info: dict):
        """Callback when internal device-to-device traffic is detected."""
        source_ip = traffic_info.get("source_ip", "unknown")
        dest_ip = traffic_info.get("dest_ip", "unknown")
        dest_port = traffic_info.get("dest_port", 0)
        protocol = traffic_info.get("protocol", "tcp")

        logger.warning(f"KAVACH: Internal traffic {source_ip} -> {dest_ip}:{dest_port}")

        # Create threat for KAAL to evaluate
        threat_info = {
            'type': 'lateral_movement',
            'severity': 'medium',
            'source_ip': source_ip,
            'target_ip': dest_ip,
            'target_port': dest_port,
            'target_device': self.network_scanner.get_device_name(dest_ip) if hasattr(self.network_scanner, 'get_device_name') else 'Unknown Device',
            'protocol': protocol,
            'packets_count': 1,
            'duration_seconds': 0,
            'description': f"Internal traffic from {source_ip} to {dest_ip}:{dest_port}",
            'detected_by': 'kavach'
        }

        # Log the threat for KAAL processing
        self.threat_logger.log_threat(
            threat_type=threat_info['type'],
            severity=threat_info['severity'],
            source_ip=threat_info['source_ip'],
            target_ip=threat_info['target_ip'],
            target_device=threat_info['target_device'],
            target_port=threat_info['target_port'],
            protocol=threat_info['protocol'],
            packets_count=threat_info['packets_count'],
            duration_seconds=threat_info['duration_seconds'],
            detected_by=threat_info['detected_by']
        )

        # Emit alert to dashboard
        self._emit_event('alert', {
            'message': f"Internal traffic detected: {source_ip} → {dest_ip}:{dest_port}",
            'severity': 'warning',
            'source_ip': source_ip,
            'target_ip': dest_ip
        })

    def _run_flask_app(self):
        """Run the Flask dashboard application."""
        from api.app import socketio

        self.socketio = socketio

        host = self.config.get("api", {}).get("host", "0.0.0.0")
        port = self.config.get("api", {}).get("port", 5000)
        debug = self.config.get("general", {}).get("debug", False)

        socketio.run(
            self.app,
            host=host,
            port=port,
            debug=debug,
            use_reloader=False,
            log_output=False
        )

    def get_status(self) -> dict:
        """Get current system status."""
        status = {
            "running": self.running,
            "mode": "gateway" if self.gateway_mode else ("simulation" if self.simulation_mode else "standalone"),
            "devices_count": len(self.network_scanner.devices),
            "threats_count": self.threat_logger.get_threat_count(),
            "honeypots_active": self.deception_engine.get_active_count(),
            "ai_model_loaded": self.agentic_defender.model_loaded,
            "gateway_mode": self.gateway_mode
        }

        # Add gateway-specific status if in gateway mode
        if self.gateway_mode and self.gateway:
            status["gateway_status"] = self.gateway.get_status()
            status["connected_devices"] = self.gateway.get_connected_devices()
            status["isolated_devices"] = len(self.gateway.isolated_devices)
            status["active_redirections"] = len(self.gateway.redirection_rules)

        # Add packet filter stats if available
        if self.packet_filter:
            status["traffic_stats"] = self.packet_filter.get_traffic_stats()
            status["blocked_ips"] = self.packet_filter.get_blocked_ips()

        # Add IDS classifier stats
        if hasattr(self, 'ids_classifier'):
            status["ids"] = self.ids_classifier.get_statistics()

        return status


@click.command()
@click.option("--config", "-c", default="config/config.yaml", help="Path to config file")
@click.option("--standalone", is_flag=True, help="Run in standalone mode (passive monitoring, for testing only)")
@click.option("--simulate", "-s", is_flag=True, help="Run with simulated devices (testing only)")
@click.option("--debug", "-d", is_flag=True, help="Enable debug logging")
@click.option("--port", "-p", default=5000, help="Dashboard port")
@click.option("--skip-checks", is_flag=True, help="Skip prerequisite checks (dangerous)")
def main(config: str, standalone: bool, simulate: bool, debug: bool, port: int, skip_checks: bool):
    """
    RAKSHAK - Agentic AI Cyber Guardian for Home IoT

    INLINE SECURITY GATEWAY MODE (DEFAULT):
      RAKSHAK operates as the network gateway between your modem and router.
      This provides full traffic control including:
      - Real device isolation via iptables
      - Traffic blocking and rate limiting
      - Honeypot redirection via NAT
      - Deep packet inspection

    Network Topology:
      Internet -> Modem -> [RAKSHAK/Jetson] -> Router (AP mode) -> IoT Devices

    STANDALONE MODE (--standalone):
      Legacy passive monitoring mode. For testing only.
      Does NOT provide real traffic control.

    Requirements for Gateway Mode:
      - Root privileges (sudo)
      - Two network interfaces (eth0 for WAN, eth1 for LAN)
      - USB-to-Ethernet adapter if Jetson has single NIC
    """
    # Print banner
    print_banner()

    # Load configuration
    cfg = load_config(config)

    # Override config with CLI options
    if simulate:
        cfg["simulation"]["enabled"] = True
        console.print("[yellow]SIMULATION MODE - Using fake devices[/yellow]")
    if debug:
        cfg["general"]["debug"] = True
        cfg["general"]["log_level"] = "DEBUG"
    if port != 5000:
        cfg["api"]["port"] = port

    # Determine mode
    gateway_mode = not standalone

    if gateway_mode:
        # =====================================================================
        # GATEWAY MODE (DEFAULT)
        # =====================================================================
        console.print("\n[bold cyan]" + "=" * 60 + "[/bold cyan]")
        console.print("[bold cyan]       RAKSHAK INLINE SECURITY GATEWAY MODE[/bold cyan]")
        console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]\n")

        if not skip_checks:
            # Check prerequisites
            console.print("[dim]Checking gateway prerequisites...[/dim]")
            ready, issues = check_gateway_prerequisites()

            if not ready:
                console.print("\n[bold red]GATEWAY PREREQUISITES NOT MET:[/bold red]")
                for issue in issues:
                    console.print(f"  [red]x[/red] {issue}")
                console.print("\n[yellow]Options:[/yellow]")
                console.print("  1. Fix the issues above and retry")
                console.print("  2. Run with --standalone for passive monitoring (limited functionality)")
                console.print("  3. Run with --skip-checks to bypass (dangerous, may not work)")
                sys.exit(1)
            else:
                console.print("[green]All prerequisites met[/green]\n")

        # Auto-detect interfaces if needed
        wan_iface = cfg.get("gateway", {}).get("wan_interface", "eth0")
        lan_iface = cfg.get("gateway", {}).get("lan_interface", "eth1")

        if cfg.get("gateway", {}).get("auto_detect_interfaces", True):
            detected_wan, detected_lan = detect_network_interfaces()
            if detected_wan and detected_lan:
                wan_iface = detected_wan
                lan_iface = detected_lan
                console.print(f"[dim]Auto-detected interfaces: WAN={wan_iface}, LAN={lan_iface}[/dim]")

        # Update config with detected interfaces
        cfg["gateway"]["wan_interface"] = wan_iface
        cfg["gateway"]["lan_interface"] = lan_iface
        cfg["gateway"]["enabled"] = True

        console.print(f"[cyan]Network Topology:[/cyan]")
        console.print(f"  Internet -> Modem -> [{wan_iface}] JETSON [{lan_iface}] -> Router (AP) -> IoT")
        console.print(f"  Gateway IP: {cfg['gateway']['lan_ip']}")

        dhcp_start = cfg.get("gateway", {}).get("dhcp", {}).get("range_start", cfg.get("gateway", {}).get("dhcp_range_start", "192.168.100.10"))
        dhcp_end = cfg.get("gateway", {}).get("dhcp", {}).get("range_end", cfg.get("gateway", {}).get("dhcp_range_end", "192.168.100.250"))
        console.print(f"  DHCP Range: {dhcp_start} - {dhcp_end}")
        console.print("")

    else:
        # =====================================================================
        # STANDALONE MODE (Legacy/Testing)
        # =====================================================================
        console.print("\n[bold yellow]" + "=" * 60 + "[/bold yellow]")
        console.print("[bold yellow]       RAKSHAK STANDALONE MODE (LIMITED)[/bold yellow]")
        console.print("[bold yellow]" + "=" * 60 + "[/bold yellow]\n")
        console.print("[yellow]WARNING: Standalone mode does NOT provide real traffic control.[/yellow]")
        console.print("[yellow]Device isolation and honeypot redirection are SIMULATED ONLY.[/yellow]")
        console.print("[yellow]Use gateway mode for real autonomous defense.[/yellow]\n")
        cfg["gateway"]["enabled"] = False

    # Setup logging
    setup_logging(cfg)

    # Create orchestrator
    try:
        orchestrator = RakshakOrchestrator(cfg, gateway_mode=gateway_mode)
    except RuntimeError as e:
        console.print(f"[bold red]ERROR: {e}[/bold red]")
        console.print("[dim]Run with --standalone for passive monitoring mode[/dim]")
        sys.exit(1)

    # Handle shutdown signals
    def signal_handler(signum, frame):
        console.print("\n[yellow]Shutting down RAKSHAK...[/yellow]")
        orchestrator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start the system
    try:
        orchestrator.start()
    except KeyboardInterrupt:
        orchestrator.stop()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        orchestrator.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
