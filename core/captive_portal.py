#!/usr/bin/env python3
"""
RAKSHAK Captive Portal - DWAAR (द्वार - Gateway/Door)
=====================================================

Info-only captive portal for new devices connecting to the
RAKSHAK-protected network. Shows RAKSHAK branding, active
security features, and network information.

Modes:
- Gateway mode: iptables DNAT redirect of HTTP to portal
- Standalone mode: Portal accessible at /portal URL

Author: Team RAKSHAK
"""

import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, Set, Optional

from loguru import logger


class CaptivePortal:
    """
    DWAAR - Captive Portal Manager

    Manages:
    - Tracking which devices have seen the portal
    - iptables rules for HTTP redirection (gateway mode)
    - Auto-release after timeout (for IoT/headless devices)
    """

    CHAIN_NAME = "RAKSHAK_PORTAL"

    def __init__(self, config: dict, gateway=None):
        """
        Initialize captive portal.

        Args:
            config: Application configuration dict
            gateway: RakshakGateway instance (None for standalone mode)
        """
        self.config = config
        self.gateway = gateway
        self.is_gateway_mode = (
            gateway is not None
            and hasattr(gateway, 'is_gateway_mode')
            and gateway.is_gateway_mode
        )

        # Portal config
        portal_config = config.get("captive_portal", {})
        self.enabled = portal_config.get("enabled", True)
        self.auto_release_minutes = portal_config.get("auto_release_minutes", 5)
        self.network_name = portal_config.get("network_name", "RAKSHAK Protected Network")
        self.admin_contact = portal_config.get("admin_contact", "Network Administrator")
        self.redirect_http = portal_config.get("redirect_http", True)
        self.redirect_https = portal_config.get("redirect_https", False)

        # Device tracking
        self._acknowledged_devices: Set[str] = set()
        self._pending_devices: Dict[str, datetime] = {}
        self._lock = threading.Lock()

        # Gateway details
        self._gateway_ip = config.get("gateway", {}).get("lan_ip", "10.42.0.1")
        self._portal_port = config.get("api", {}).get("port", 5000)

        logger.info(
            f"Captive Portal (DWAAR) initialized "
            f"(gateway_mode={self.is_gateway_mode}, enabled={self.enabled})"
        )

    # =========================================================================
    # iptables Chain Management
    # =========================================================================

    def setup_portal_chain(self):
        """Create RAKSHAK_PORTAL chain in nat table and insert PREROUTING jump."""
        if not self.is_gateway_mode:
            return

        try:
            # Create chain (ignore error if already exists)
            subprocess.run(
                ["iptables", "-t", "nat", "-N", self.CHAIN_NAME],
                capture_output=True
            )
            # Flush any existing rules
            subprocess.run(
                ["iptables", "-t", "nat", "-F", self.CHAIN_NAME],
                capture_output=True
            )
            # Insert jump into PREROUTING at position 1 (before honeypot chain)
            subprocess.run(
                ["iptables", "-t", "nat", "-I", "PREROUTING", "1",
                 "-j", self.CHAIN_NAME],
                capture_output=True
            )
            logger.info("DWAAR: Portal iptables chain created")
        except Exception as e:
            logger.error(f"DWAAR: Failed to setup portal chain: {e}")

    def cleanup_portal_chain(self):
        """Remove RAKSHAK_PORTAL chain and PREROUTING jump."""
        if not self.is_gateway_mode:
            return

        try:
            # Remove PREROUTING jump
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "PREROUTING",
                 "-j", self.CHAIN_NAME],
                capture_output=True
            )
            # Flush and delete chain
            subprocess.run(
                ["iptables", "-t", "nat", "-F", self.CHAIN_NAME],
                capture_output=True
            )
            subprocess.run(
                ["iptables", "-t", "nat", "-X", self.CHAIN_NAME],
                capture_output=True
            )
            logger.info("DWAAR: Portal iptables chain removed")
        except Exception as e:
            logger.debug(f"DWAAR: Error cleaning up portal chain: {e}")

    # =========================================================================
    # Device Redirection
    # =========================================================================

    def redirect_device(self, device_ip: str):
        """
        Add iptables rules to redirect device's HTTP traffic to the portal.

        Args:
            device_ip: IP address of the device to redirect
        """
        if not self.is_gateway_mode:
            return

        target = f"{self._gateway_ip}:{self._portal_port}"
        comment = f"rakshak-portal-{device_ip.replace('.', '-')}"

        try:
            if self.redirect_http:
                subprocess.run([
                    "iptables", "-t", "nat", "-A", self.CHAIN_NAME,
                    "-s", device_ip,
                    "-p", "tcp", "--dport", "80",
                    "-j", "DNAT", "--to-destination", target,
                    "-m", "comment", "--comment", comment
                ], check=True, capture_output=True)

            if self.redirect_https:
                subprocess.run([
                    "iptables", "-t", "nat", "-A", self.CHAIN_NAME,
                    "-s", device_ip,
                    "-p", "tcp", "--dport", "443",
                    "-j", "DNAT", "--to-destination", target,
                    "-m", "comment", "--comment", f"{comment}-https"
                ], check=True, capture_output=True)

            logger.info(f"DWAAR: Redirecting {device_ip} HTTP to portal")
        except Exception as e:
            logger.error(f"DWAAR: Failed to redirect {device_ip}: {e}")

    def release_device(self, device_ip: str):
        """
        Remove iptables redirect rules for a device.

        Args:
            device_ip: IP address of the device to release
        """
        if not self.is_gateway_mode:
            return

        comment = f"rakshak-portal-{device_ip.replace('.', '-')}"

        try:
            # Find and delete rules matching this device's comment
            result = subprocess.run(
                ["iptables", "-t", "nat", "-L", self.CHAIN_NAME,
                 "-n", "--line-numbers"],
                capture_output=True, text=True
            )

            # Collect line numbers to delete (in reverse order)
            lines_to_delete = []
            for line in result.stdout.split("\n"):
                if comment in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        lines_to_delete.append(int(parts[0]))

            # Delete in reverse order to maintain line numbers
            for line_num in sorted(lines_to_delete, reverse=True):
                subprocess.run(
                    ["iptables", "-t", "nat", "-D", self.CHAIN_NAME,
                     str(line_num)],
                    capture_output=True
                )

            if lines_to_delete:
                logger.info(f"DWAAR: Released {device_ip} from portal redirect")
        except Exception as e:
            logger.debug(f"DWAAR: Error releasing {device_ip}: {e}")

    # =========================================================================
    # Device Tracking
    # =========================================================================

    def acknowledge_portal(self, device_ip: str):
        """
        Mark a device as having seen the portal and release its redirect.

        Args:
            device_ip: IP address of the device
        """
        with self._lock:
            self._acknowledged_devices.add(device_ip)
            self._pending_devices.pop(device_ip, None)

        self.release_device(device_ip)
        logger.info(f"DWAAR: Device {device_ip} acknowledged portal")

    def is_device_acknowledged(self, device_ip: str) -> bool:
        """Check if a device has already seen the portal."""
        with self._lock:
            return device_ip in self._acknowledged_devices

    def on_new_device(self, device_ip: str, enrollment_status: str = "unknown"):
        """
        Called when the network scanner discovers a new/unknown device.

        Args:
            device_ip: IP of the new device
            enrollment_status: Device enrollment status
        """
        if not self.enabled:
            return

        # Skip if already acknowledged or pending
        with self._lock:
            if device_ip in self._acknowledged_devices:
                return
            if device_ip in self._pending_devices:
                return

            # Skip the gateway itself
            if device_ip == self._gateway_ip:
                return

            self._pending_devices[device_ip] = datetime.now()

        # Add iptables redirect in gateway mode
        if self.is_gateway_mode:
            self.redirect_device(device_ip)

        logger.info(f"DWAAR: New device {device_ip} added to captive portal")

    def check_auto_release(self):
        """Auto-release devices that have been pending for too long."""
        if not self.enabled:
            return

        now = datetime.now()
        threshold = timedelta(minutes=self.auto_release_minutes)

        with self._lock:
            expired = [
                ip for ip, first_seen in self._pending_devices.items()
                if now - first_seen > threshold
            ]

        for ip in expired:
            self.acknowledge_portal(ip)
            logger.info(f"DWAAR: Auto-released {ip} (timeout after {self.auto_release_minutes}min)")

    # =========================================================================
    # Portal Context
    # =========================================================================

    def get_portal_context(self, orchestrator=None) -> dict:
        """
        Build template context for the portal page.

        Args:
            orchestrator: RakshakOrchestrator instance for live stats

        Returns:
            Dict of template variables
        """
        context = {
            "network_name": self.network_name,
            "admin_contact": self.admin_contact,
            "version": self.config.get("general", {}).get("version", "1.0.0"),
            "device_count": 0,
            "honeypot_count": 0,
            "ai_active": False,
            "threats_blocked": 0,
            "continue_url": "/portal/ack",
            "acknowledged": False,
        }

        if orchestrator:
            try:
                context["device_count"] = len(orchestrator.network_scanner.devices)
            except Exception:
                pass
            try:
                context["honeypot_count"] = orchestrator.deception_engine.get_active_count()
            except Exception:
                pass
            try:
                context["ai_active"] = orchestrator.agentic_defender.model_loaded
            except Exception:
                pass
            try:
                context["threats_blocked"] = orchestrator.threat_logger.get_threat_count()
            except Exception:
                pass

        return context

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def stop(self):
        """Cleanup all portal rules and state."""
        # Release all pending devices
        with self._lock:
            pending_ips = list(self._pending_devices.keys())

        for ip in pending_ips:
            self.release_device(ip)

        # Remove iptables chain
        self.cleanup_portal_chain()

        logger.info("DWAAR: Captive portal stopped")
