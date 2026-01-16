"""
RAKSHAK Packet Filter Module
============================

Provides deep packet inspection and traffic control using iptables and nfqueue.
Enables real-time traffic analysis and blocking capabilities.

Features:
- Deep packet inspection
- Real-time traffic blocking
- Protocol detection
- Malicious payload detection
- Traffic logging and analysis
"""

import os
import subprocess
import threading
import queue
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Set
from datetime import datetime
from enum import Enum

from loguru import logger

# Try to import scapy for packet inspection
try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - packet inspection disabled")

# Try to import netfilterqueue for inline packet processing
try:
    from netfilterqueue import NetfilterQueue
    NFQUEUE_AVAILABLE = True
except ImportError:
    NFQUEUE_AVAILABLE = False
    logger.warning("NetfilterQueue not available - using iptables-only mode")


class TrafficAction(Enum):
    """Actions for traffic filtering"""
    ACCEPT = "accept"
    DROP = "drop"
    REDIRECT = "redirect"
    LOG = "log"
    RATE_LIMIT = "rate_limit"


@dataclass
class FirewallRule:
    """Represents a firewall rule"""
    id: str
    action: TrafficAction
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None  # tcp, udp, icmp
    direction: str = "forward"  # input, output, forward
    priority: int = 100
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    is_active: bool = True


@dataclass
class TrafficEvent:
    """Represents a captured traffic event"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    payload_preview: Optional[str] = None
    flags: Optional[str] = None
    action_taken: TrafficAction = TrafficAction.ACCEPT


class PacketFilter:
    """
    RAKSHAK Packet Filter

    Provides traffic control and inspection capabilities.
    Works with iptables for blocking and nfqueue for inspection.
    """

    def __init__(self, lan_interface: str = "eth1"):
        self.lan_interface = lan_interface
        self.rules: Dict[str, FirewallRule] = {}
        self.blocked_ips: Set[str] = set()
        self.rate_limited_ips: Dict[str, str] = {}  # ip -> limit
        self.traffic_log: List[TrafficEvent] = []
        self.max_log_size = 10000

        self.is_running = False
        self.packet_queue = queue.Queue(maxsize=1000)

        # Callbacks for packet events
        self.on_threat_detected: Optional[Callable] = None
        self.on_packet_blocked: Optional[Callable] = None

        # Suspicious patterns to detect
        self.suspicious_ports = {
            23: "telnet",
            4444: "metasploit",
            5555: "android_debug",
            6667: "irc_botnet",
            31337: "elite_backdoor"
        }

        self.suspicious_payloads = [
            b"/bin/sh",
            b"/bin/bash",
            b"wget ",
            b"curl ",
            b"nc -e",
            b"chmod 777",
            b"rm -rf",
            b"base64 -d",
            b"python -c"
        ]

        logger.info("PacketFilter initialized")

    def setup_nfqueue(self, queue_num: int = 1) -> bool:
        """Setup nfqueue for inline packet inspection"""
        if not NFQUEUE_AVAILABLE:
            logger.warning("nfqueue not available, using iptables-only mode")
            return False

        try:
            # Add iptables rule to send packets to nfqueue
            subprocess.run([
                "iptables", "-I", "FORWARD", "1",
                "-j", "NFQUEUE", "--queue-num", str(queue_num)
            ], check=True, capture_output=True)

            logger.info(f"nfqueue {queue_num} configured")
            return True

        except Exception as e:
            logger.error(f"Failed to setup nfqueue: {e}")
            return False

    def start_packet_inspection(self, queue_num: int = 1):
        """Start inline packet inspection using nfqueue"""
        if not NFQUEUE_AVAILABLE:
            logger.warning("nfqueue not available")
            return

        def process_packet(packet):
            """Process each packet through nfqueue"""
            try:
                # Parse with scapy
                if SCAPY_AVAILABLE:
                    pkt = IP(packet.get_payload())

                    # Extract info
                    src_ip = pkt.src
                    dst_ip = pkt.dst
                    protocol = "unknown"
                    src_port = 0
                    dst_port = 0

                    if TCP in pkt:
                        protocol = "tcp"
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                    elif UDP in pkt:
                        protocol = "udp"
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                    elif ICMP in pkt:
                        protocol = "icmp"

                    # Check if should block
                    if src_ip in self.blocked_ips:
                        packet.drop()
                        self._log_traffic(src_ip, dst_ip, src_port, dst_port,
                                         protocol, len(packet.get_payload()),
                                         TrafficAction.DROP)
                        return

                    # Check for suspicious patterns
                    if self._check_suspicious(pkt, src_ip, dst_ip, dst_port):
                        if self.on_threat_detected:
                            self.on_threat_detected({
                                "source_ip": src_ip,
                                "dest_ip": dst_ip,
                                "dest_port": dst_port,
                                "protocol": protocol,
                                "reason": "suspicious_traffic"
                            })

                # Accept packet
                packet.accept()

            except Exception as e:
                logger.error(f"Packet processing error: {e}")
                packet.accept()  # Accept on error to avoid blocking legitimate traffic

        try:
            nfqueue = NetfilterQueue()
            nfqueue.bind(queue_num, process_packet)

            self.is_running = True
            logger.info("Packet inspection started")

            while self.is_running:
                nfqueue.run_socket(nfqueue.get_fd())

        except Exception as e:
            logger.error(f"Packet inspection error: {e}")
        finally:
            if 'nfqueue' in locals():
                nfqueue.unbind()

    def _check_suspicious(self, packet, src_ip: str, dst_ip: str, dst_port: int) -> bool:
        """Check packet for suspicious patterns"""
        suspicious = False

        # Check suspicious ports
        if dst_port in self.suspicious_ports:
            logger.warning(f"Suspicious port {dst_port} ({self.suspicious_ports[dst_port]}) from {src_ip}")
            suspicious = True

        # Check payload for malicious patterns
        if Raw in packet:
            payload = packet[Raw].load
            for pattern in self.suspicious_payloads:
                if pattern in payload:
                    logger.warning(f"Suspicious payload pattern from {src_ip}: {pattern}")
                    suspicious = True
                    break

        return suspicious

    def _log_traffic(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    protocol: str, size: int, action: TrafficAction):
        """Log traffic event"""
        event = TrafficEvent(
            timestamp=datetime.now(),
            source_ip=src_ip,
            dest_ip=dst_ip,
            source_port=src_port,
            dest_port=dst_port,
            protocol=protocol,
            packet_size=size,
            action_taken=action
        )

        self.traffic_log.append(event)

        # Trim log if too large
        if len(self.traffic_log) > self.max_log_size:
            self.traffic_log = self.traffic_log[-self.max_log_size:]

    def add_rule(self, rule: FirewallRule) -> bool:
        """Add a firewall rule"""
        try:
            # Build iptables command
            cmd = ["iptables"]

            # Chain
            if rule.direction == "input":
                cmd.extend(["-A", "INPUT"])
            elif rule.direction == "output":
                cmd.extend(["-A", "OUTPUT"])
            else:
                cmd.extend(["-A", "FORWARD"])

            # Source IP
            if rule.source_ip:
                cmd.extend(["-s", rule.source_ip])

            # Destination IP
            if rule.dest_ip:
                cmd.extend(["-d", rule.dest_ip])

            # Protocol
            if rule.protocol:
                cmd.extend(["-p", rule.protocol])

                # Ports (only for tcp/udp)
                if rule.protocol in ["tcp", "udp"]:
                    if rule.source_port:
                        cmd.extend(["--sport", str(rule.source_port)])
                    if rule.dest_port:
                        cmd.extend(["--dport", str(rule.dest_port)])

            # Action
            if rule.action == TrafficAction.DROP:
                cmd.extend(["-j", "DROP"])
            elif rule.action == TrafficAction.ACCEPT:
                cmd.extend(["-j", "ACCEPT"])
            elif rule.action == TrafficAction.LOG:
                cmd.extend(["-j", "LOG", "--log-prefix", f"[RAKSHAK-{rule.id}] "])

            # Add comment
            cmd.extend(["-m", "comment", "--comment", f"rakshak-{rule.id}"])

            # Execute
            subprocess.run(cmd, check=True, capture_output=True)

            self.rules[rule.id] = rule
            logger.info(f"Rule {rule.id} added: {rule.description}")
            return True

        except Exception as e:
            logger.error(f"Failed to add rule {rule.id}: {e}")
            return False

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a firewall rule"""
        if rule_id not in self.rules:
            return False

        try:
            # Find and delete rule by comment
            result = subprocess.run(
                ["iptables", "-L", "FORWARD", "-n", "--line-numbers"],
                capture_output=True, text=True
            )

            for line in result.stdout.split("\n"):
                if f"rakshak-{rule_id}" in line:
                    line_num = line.split()[0]
                    subprocess.run([
                        "iptables", "-D", "FORWARD", line_num
                    ], capture_output=True)
                    break

            del self.rules[rule_id]
            logger.info(f"Rule {rule_id} removed")
            return True

        except Exception as e:
            logger.error(f"Failed to remove rule {rule_id}: {e}")
            return False

    def block_ip(self, ip_address: str, reason: str = "") -> bool:
        """Block all traffic from/to an IP"""
        rule_id = f"block-{ip_address.replace('.', '-')}"

        rule = FirewallRule(
            id=rule_id,
            action=TrafficAction.DROP,
            source_ip=ip_address,
            description=f"Block {ip_address}: {reason}"
        )

        if self.add_rule(rule):
            self.blocked_ips.add(ip_address)
            return True
        return False

    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP"""
        rule_id = f"block-{ip_address.replace('.', '-')}"

        if self.remove_rule(rule_id):
            self.blocked_ips.discard(ip_address)
            return True
        return False

    def block_port(self, port: int, protocol: str = "tcp", direction: str = "both") -> bool:
        """Block a specific port"""
        rules_added = []

        if direction in ["both", "inbound"]:
            rule_id = f"block-port-{port}-{protocol}-in"
            rule = FirewallRule(
                id=rule_id,
                action=TrafficAction.DROP,
                protocol=protocol,
                dest_port=port,
                description=f"Block inbound {protocol}/{port}"
            )
            if self.add_rule(rule):
                rules_added.append(rule_id)

        if direction in ["both", "outbound"]:
            rule_id = f"block-port-{port}-{protocol}-out"
            rule = FirewallRule(
                id=rule_id,
                action=TrafficAction.DROP,
                protocol=protocol,
                source_port=port,
                description=f"Block outbound {protocol}/{port}"
            )
            if self.add_rule(rule):
                rules_added.append(rule_id)

        return len(rules_added) > 0

    def rate_limit_ip(self, ip_address: str, limit: str = "10/second") -> bool:
        """Apply rate limiting to an IP"""
        try:
            # Accept limited traffic
            subprocess.run([
                "iptables", "-I", "FORWARD", "1",
                "-s", ip_address,
                "-m", "limit", "--limit", limit,
                "-j", "ACCEPT",
                "-m", "comment", "--comment", f"rakshak-ratelimit-{ip_address}"
            ], check=True, capture_output=True)

            # Drop excess
            subprocess.run([
                "iptables", "-I", "FORWARD", "2",
                "-s", ip_address,
                "-j", "DROP",
                "-m", "comment", "--comment", f"rakshak-ratelimit-drop-{ip_address}"
            ], check=True, capture_output=True)

            self.rate_limited_ips[ip_address] = limit
            logger.info(f"Rate limit {limit} applied to {ip_address}")
            return True

        except Exception as e:
            logger.error(f"Failed to rate limit {ip_address}: {e}")
            return False

    def log_traffic_to_ip(self, ip_address: str) -> bool:
        """Enable logging for traffic to/from an IP"""
        try:
            # Log traffic from IP
            subprocess.run([
                "iptables", "-I", "FORWARD", "1",
                "-s", ip_address,
                "-j", "LOG",
                "--log-prefix", f"[RAKSHAK-{ip_address}] ",
                "-m", "comment", "--comment", f"rakshak-log-{ip_address}"
            ], check=True, capture_output=True)

            # Log traffic to IP
            subprocess.run([
                "iptables", "-I", "FORWARD", "1",
                "-d", ip_address,
                "-j", "LOG",
                "--log-prefix", f"[RAKSHAK-{ip_address}] ",
                "-m", "comment", "--comment", f"rakshak-log-to-{ip_address}"
            ], check=True, capture_output=True)

            logger.info(f"Traffic logging enabled for {ip_address}")
            return True

        except Exception as e:
            logger.error(f"Failed to enable logging for {ip_address}: {e}")
            return False

    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        return list(self.blocked_ips)

    def get_active_rules(self) -> List[Dict]:
        """Get list of active rules"""
        return [
            {
                "id": rule.id,
                "action": rule.action.value,
                "source_ip": rule.source_ip,
                "dest_ip": rule.dest_ip,
                "protocol": rule.protocol,
                "dest_port": rule.dest_port,
                "description": rule.description,
                "created_at": rule.created_at.isoformat()
            }
            for rule in self.rules.values()
            if rule.is_active
        ]

    def get_traffic_stats(self) -> Dict:
        """Get traffic statistics"""
        total = len(self.traffic_log)
        blocked = sum(1 for e in self.traffic_log if e.action_taken == TrafficAction.DROP)
        accepted = total - blocked

        # Protocol breakdown
        protocols = {}
        for event in self.traffic_log[-1000:]:  # Last 1000 events
            protocols[event.protocol] = protocols.get(event.protocol, 0) + 1

        return {
            "total_packets_logged": total,
            "packets_blocked": blocked,
            "packets_accepted": accepted,
            "blocked_ips_count": len(self.blocked_ips),
            "active_rules_count": len(self.rules),
            "rate_limited_ips": len(self.rate_limited_ips),
            "protocol_breakdown": protocols
        }

    def flush_all_rules(self) -> bool:
        """Remove all RAKSHAK rules"""
        try:
            # Get all rules with rakshak comment
            result = subprocess.run(
                ["iptables", "-L", "FORWARD", "-n", "--line-numbers"],
                capture_output=True, text=True
            )

            # Collect line numbers to delete (in reverse order)
            lines_to_delete = []
            for line in result.stdout.split("\n"):
                if "rakshak-" in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        lines_to_delete.append(int(parts[0]))

            # Delete in reverse order to maintain line numbers
            for line_num in sorted(lines_to_delete, reverse=True):
                subprocess.run([
                    "iptables", "-D", "FORWARD", str(line_num)
                ], capture_output=True)

            # Also flush NAT rules
            result = subprocess.run(
                ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"],
                capture_output=True, text=True
            )

            lines_to_delete = []
            for line in result.stdout.split("\n"):
                if "rakshak-" in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        lines_to_delete.append(int(parts[0]))

            for line_num in sorted(lines_to_delete, reverse=True):
                subprocess.run([
                    "iptables", "-t", "nat", "-D", "PREROUTING", str(line_num)
                ], capture_output=True)

            self.rules.clear()
            self.blocked_ips.clear()
            self.rate_limited_ips.clear()

            logger.info("All RAKSHAK firewall rules flushed")
            return True

        except Exception as e:
            logger.error(f"Failed to flush rules: {e}")
            return False

    def stop(self):
        """Stop packet filter"""
        self.is_running = False
        logger.info("PacketFilter stopped")


# Predefined security rules
def apply_default_security_rules(packet_filter: PacketFilter):
    """Apply default security rules"""

    # Block known malicious ports
    malicious_ports = [
        (4444, "metasploit_default"),
        (5555, "android_adb"),
        (6667, "irc_botnet"),
        (31337, "elite_backdoor"),
        (1234, "common_backdoor"),
        (12345, "netbus_trojan")
    ]

    for port, name in malicious_ports:
        packet_filter.block_port(port, "tcp", "both")
        logger.info(f"Blocked malicious port {port} ({name})")

    # Log all telnet traffic
    packet_filter.add_rule(FirewallRule(
        id="log-telnet",
        action=TrafficAction.LOG,
        protocol="tcp",
        dest_port=23,
        description="Log telnet connections"
    ))

    logger.info("Default security rules applied")


if __name__ == "__main__":
    # Test packet filter
    pf = PacketFilter()

    print("Packet Filter Test")
    print(f"Scapy available: {SCAPY_AVAILABLE}")
    print(f"nfqueue available: {NFQUEUE_AVAILABLE}")

    # Test blocking an IP
    print("\nTo test, run as root:")
    print("  sudo python packet_filter.py")
