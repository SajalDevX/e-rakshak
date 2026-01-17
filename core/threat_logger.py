#!/usr/bin/env python3
"""
RAKSHAK Threat Logger
=====================

Central logging and threat management system.

Features:
- Thread-safe threat queue for async processing
- Event logging with structured format
- CCTNS export for law enforcement
- JSON and SQLite storage

Author: Team RAKSHAK
"""

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

from loguru import logger


class ThreatSeverity(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of threats detected."""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    DOS_ATTACK = "dos_attack"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"


class ActionType(Enum):
    """Actions taken by KAAL agent."""
    MONITOR = "monitor"
    DEPLOY_HONEYPOT = "deploy_honeypot"
    ISOLATE_DEVICE = "isolate_device"
    ENGAGE_ATTACKER = "engage_attacker"
    ALERT_USER = "alert_user"


@dataclass
class ThreatEvent:
    """Structured threat event."""
    id: str
    timestamp: str
    type: str
    severity: str
    source_ip: str
    source_port: int
    target_ip: str
    target_port: int
    target_device: str
    protocol: str
    payload: str
    packets_count: int
    duration_seconds: float
    detected_by: str
    raw_data: dict

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ActionEvent:
    """Structured action event."""
    id: str
    timestamp: str
    threat_id: str
    action: str
    target: str
    status: str
    details: dict

    def to_dict(self) -> dict:
        return asdict(self)


class ThreatLogger:
    """
    Central threat logging and management system.

    Provides:
    - Thread-safe threat queue
    - Event logging
    - Database storage
    - CCTNS export
    """

    def __init__(self, config: dict):
        """Initialize the threat logger."""
        self.config = config
        self.logging_config = config.get("logging", {})

        # Thread-safe queues
        self.threat_queue: Queue[ThreatEvent] = Queue()
        self.action_queue: Queue[ActionEvent] = Queue()

        # In-memory storage for recent events
        self.recent_threats: List[ThreatEvent] = []
        self.recent_actions: List[ActionEvent] = []
        self.max_recent = 1000

        # Locks for thread safety
        self._threats_lock = threading.Lock()
        self._actions_lock = threading.Lock()

        # Statistics
        self.stats = {
            "total_threats": 0,
            "total_actions": 0,
            "threats_by_type": {},
            "threats_by_severity": {},
            "actions_by_type": {}
        }

        # Initialize database
        self._init_database()

        # Event ID counter
        self._event_counter = 0
        self._counter_lock = threading.Lock()

        logger.info("ThreatLogger initialized")

    def _init_database(self):
        """Initialize SQLite database for persistent storage."""
        db_config = self.config.get("database", {})
        db_path = Path(db_config.get("path", "data/rakshak.db"))
        db_path.parent.mkdir(parents=True, exist_ok=True)

        self.db_path = db_path
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Create threats table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                source_port INTEGER,
                target_ip TEXT,
                target_port INTEGER,
                target_device TEXT,
                protocol TEXT,
                payload TEXT,
                packets_count INTEGER,
                duration_seconds REAL,
                detected_by TEXT,
                raw_data TEXT
            )
        """)

        # Create actions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                threat_id TEXT,
                action TEXT NOT NULL,
                target TEXT,
                status TEXT,
                details TEXT,
                FOREIGN KEY (threat_id) REFERENCES threats(id)
            )
        """)

        # Create devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                mac TEXT,
                hostname TEXT,
                device_type TEXT,
                os TEXT,
                risk_score INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT,
                enrollment_status TEXT DEFAULT 'unknown',
                zone TEXT DEFAULT 'guest',
                enrollment_date TEXT,
                enrolled_by TEXT,
                firewall_rules_applied TEXT,
                isolation_level TEXT,
                isolation_reason TEXT,
                isolated_at TEXT
            )
        """)

        # Zero Trust: Zone change history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS zone_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT NOT NULL,
                old_zone TEXT,
                new_zone TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                changed_by TEXT,
                reason TEXT,
                FOREIGN KEY (device_mac) REFERENCES devices(mac)
            )
        """)

        # Zero Trust: Enrollment audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS enrollment_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT NOT NULL,
                action TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT,
                zone_assigned TEXT,
                performed_by TEXT,
                performed_at TEXT NOT NULL,
                FOREIGN KEY (device_mac) REFERENCES devices(mac)
            )
        """)

        # Zero Trust: Persistent isolation state
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS persistent_isolations (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                isolation_level TEXT NOT NULL,
                reason TEXT,
                isolated_at TEXT NOT NULL,
                expires_at TEXT,
                is_active INTEGER DEFAULT 1
            )
        """)

        # Zero Trust: Device behavior baselines
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_baselines (
                device_ip TEXT PRIMARY KEY,
                device_mac TEXT,
                baseline_start TEXT NOT NULL,
                total_flows INTEGER DEFAULT 0,
                status TEXT DEFAULT 'learning',
                protocols_used TEXT,
                common_dst_ports TEXT,
                internal_peers TEXT,
                avg_bytes_per_flow REAL,
                active_hours TEXT,
                last_updated TEXT
            )
        """)

        # Device Fingerprinting: Multi-signal fingerprints
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_fingerprints (
                device_mac TEXT PRIMARY KEY,
                device_ip TEXT NOT NULL,
                ja3_hash TEXT,
                ja3_confidence REAL,
                ja3_vendor TEXT,
                ja3_device_type TEXT,
                dhcp_option55 TEXT,
                dhcp_confidence REAL,
                dhcp_os TEXT,
                tcp_signature TEXT,
                tcp_confidence REAL,
                tcp_os TEXT,
                dns_domains TEXT,
                dns_confidence REAL,
                dns_vendor TEXT,
                fused_vendor TEXT,
                fused_device_type TEXT,
                fused_os TEXT,
                overall_confidence REAL,
                identity_status TEXT DEFAULT 'UNKNOWN',
                first_seen TEXT NOT NULL,
                last_updated TEXT NOT NULL,
                fingerprint_complete INTEGER DEFAULT 0,
                FOREIGN KEY (device_mac) REFERENCES devices(mac)
            )
        """)

        # Device Fingerprinting: Confidence tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_confidence (
                device_ip TEXT PRIMARY KEY,
                device_mac TEXT,
                confidence_score REAL DEFAULT 0.0,
                state TEXT DEFAULT 'DISCOVERED',
                signals_collected INTEGER DEFAULT 0,
                anomaly_count INTEGER DEFAULT 0,
                drift_score REAL DEFAULT 0.0,
                last_confidence_update TEXT,
                confidence_decay_rate REAL DEFAULT 0.01,
                re_evaluation_needed INTEGER DEFAULT 0,
                FOREIGN KEY (device_ip) REFERENCES devices(ip),
                FOREIGN KEY (device_mac) REFERENCES devices(mac)
            )
        """)

        # Device Fingerprinting: Signal history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fingerprint_signal_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT NOT NULL,
                signal_type TEXT NOT NULL,
                signal_value TEXT,
                confidence REAL,
                captured_at TEXT NOT NULL,
                FOREIGN KEY (device_mac) REFERENCES devices(mac)
            )
        """)

        # Device Fingerprinting: Cloud endpoint mappings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_cloud_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                device_mac TEXT NOT NULL,
                domain TEXT NOT NULL,
                resolved_ip TEXT,
                vendor TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                query_count INTEGER DEFAULT 1,
                FOREIGN KEY (device_ip) REFERENCES devices(ip)
            )
        """)

        # Zero Trust: Device anomalies
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_anomalies (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                anomaly_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                deviation_score REAL,
                FOREIGN KEY (device_ip) REFERENCES device_baselines(device_ip)
            )
        """)

        # Zero Trust: Attack chains
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_chains (
                chain_id TEXT PRIMARY KEY,
                root_device_ip TEXT NOT NULL,
                compromised_devices TEXT,
                attack_sequence TEXT,
                first_seen TEXT NOT NULL,
                last_activity TEXT NOT NULL,
                chain_length INTEGER,
                severity TEXT,
                is_active INTEGER DEFAULT 1
            )
        """)

        # Enhanced Detection: ARP spoofing events
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS arp_spoofing_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                victim_ip TEXT NOT NULL,
                real_mac TEXT,
                fake_mac TEXT NOT NULL,
                attack_type TEXT,
                severity TEXT NOT NULL,
                confidence REAL,
                action_taken TEXT
            )
        """)

        # Enhanced Detection: Port scan events
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS port_scan_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                scanner_ip TEXT NOT NULL,
                ports_scanned TEXT,
                scan_type TEXT NOT NULL,
                severity TEXT,
                confidence REAL,
                action_taken TEXT
            )
        """)

        # Enhanced Detection: Identity drift events
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS identity_drift_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                device_mac TEXT,
                drift_score REAL NOT NULL,
                drift_type TEXT,
                severity TEXT NOT NULL,
                baseline_protocols TEXT,
                current_protocols TEXT,
                baseline_ports TEXT,
                current_ports TEXT,
                action_taken TEXT
            )
        """)

        conn.commit()
        conn.close()
        logger.debug(f"Database initialized at {db_path}")

    def _generate_id(self, prefix: str = "EVT") -> str:
        """Generate unique event ID."""
        with self._counter_lock:
            self._event_counter += 1
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            return f"{prefix}-{timestamp}-{self._event_counter:06d}"

    def log_threat(
        self,
        threat_type: str,
        severity: str,
        source_ip: str,
        target_ip: str,
        target_device: str = "unknown",
        source_port: int = 0,
        target_port: int = 0,
        protocol: str = "tcp",
        payload: str = "",
        packets_count: int = 1,
        duration_seconds: float = 0.0,
        detected_by: str = "network_scanner",
        raw_data: dict = None
    ) -> ThreatEvent:
        """
        Log a new threat event.

        Args:
            threat_type: Type of threat (port_scan, brute_force, etc.)
            severity: Severity level (low, medium, high, critical)
            source_ip: Attacker IP address
            target_ip: Target device IP
            target_device: Target device name
            source_port: Source port
            target_port: Target port
            protocol: Network protocol
            payload: Captured payload (truncated)
            packets_count: Number of packets
            duration_seconds: Attack duration
            detected_by: Detection module name
            raw_data: Additional raw data

        Returns:
            ThreatEvent object
        """
        event = ThreatEvent(
            id=self._generate_id("THR"),
            timestamp=datetime.now().isoformat(),
            type=threat_type,
            severity=severity,
            source_ip=source_ip,
            source_port=source_port,
            target_ip=target_ip,
            target_port=target_port,
            target_device=target_device,
            protocol=protocol,
            payload=payload[:500] if payload else "",  # Truncate payload
            packets_count=packets_count,
            duration_seconds=duration_seconds,
            detected_by=detected_by,
            raw_data=raw_data or {}
        )

        # Add to queue for async processing
        self.threat_queue.put(event)

        # Add to recent list
        with self._threats_lock:
            self.recent_threats.append(event)
            if len(self.recent_threats) > self.max_recent:
                self.recent_threats.pop(0)

        # Update statistics
        self.stats["total_threats"] += 1
        self.stats["threats_by_type"][threat_type] = \
            self.stats["threats_by_type"].get(threat_type, 0) + 1
        self.stats["threats_by_severity"][severity] = \
            self.stats["threats_by_severity"].get(severity, 0) + 1

        # Save to database
        self._save_threat_to_db(event)

        logger.warning(
            f"THREAT: {threat_type} | {severity} | {source_ip} -> {target_device}"
        )

        return event

    def log_action(
        self,
        threat_id: str,
        action: str,
        target: str,
        status: str = "executed",
        details: dict = None
    ) -> ActionEvent:
        """
        Log an action taken in response to a threat.

        Args:
            threat_id: ID of the threat this action responds to
            action: Action type (monitor, deploy_honeypot, etc.)
            target: Target of the action
            status: Action status
            details: Additional details

        Returns:
            ActionEvent object
        """
        event = ActionEvent(
            id=self._generate_id("ACT"),
            timestamp=datetime.now().isoformat(),
            threat_id=threat_id,
            action=action,
            target=target,
            status=status,
            details=details or {}
        )

        # Add to queue
        self.action_queue.put(event)

        # Add to recent list
        with self._actions_lock:
            self.recent_actions.append(event)
            if len(self.recent_actions) > self.max_recent:
                self.recent_actions.pop(0)

        # Update statistics
        self.stats["total_actions"] += 1
        self.stats["actions_by_type"][action] = \
            self.stats["actions_by_type"].get(action, 0) + 1

        # Save to database
        self._save_action_to_db(event)

        logger.info(f"ACTION: {action} | {target} | {status}")

        return event

    def log_decision(self, threat: dict, action: dict):
        """Log a decision made by KAAL agent."""
        return self.log_action(
            threat_id=threat.get("id", "unknown"),
            action=action.get("action", "unknown"),
            target=action.get("target", "unknown"),
            status=action.get("status", "executed"),
            details={
                "confidence": action.get("confidence", 0),
                "q_value": action.get("q_value", 0),
                "threat_severity": threat.get("severity", "unknown")
            }
        )

    def _save_threat_to_db(self, event: ThreatEvent):
        """Save threat event to database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threats
                (id, timestamp, type, severity, source_ip, source_port,
                 target_ip, target_port, target_device, protocol, payload,
                 packets_count, duration_seconds, detected_by, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.id, event.timestamp, event.type, event.severity,
                event.source_ip, event.source_port, event.target_ip,
                event.target_port, event.target_device, event.protocol,
                event.payload, event.packets_count, event.duration_seconds,
                event.detected_by, json.dumps(event.raw_data)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to save threat to DB: {e}")

    def _save_action_to_db(self, event: ActionEvent):
        """Save action event to database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO actions
                (id, timestamp, threat_id, action, target, status, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event.id, event.timestamp, event.threat_id,
                event.action, event.target, event.status,
                json.dumps(event.details)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to save action to DB: {e}")

    def get_next_threat(self, timeout: float = 0.5) -> Optional[dict]:
        """Get next threat from queue for processing."""
        try:
            event = self.threat_queue.get(timeout=timeout)
            return event.to_dict()
        except Empty:
            return None

    def get_recent_threats(self, limit: int = 50) -> List[dict]:
        """Get recent threat events."""
        with self._threats_lock:
            threats = self.recent_threats[-limit:]
            return [t.to_dict() for t in threats]

    def get_recent_actions(self, limit: int = 50) -> List[dict]:
        """Get recent action events."""
        with self._actions_lock:
            actions = self.recent_actions[-limit:]
            return [a.to_dict() for a in actions]

    def get_threat_count(self) -> int:
        """Get total threat count."""
        return self.stats["total_threats"]

    def get_statistics(self) -> dict:
        """Get threat and action statistics."""
        return self.stats.copy()

    def export_cctns(self, filepath: str = None) -> str:
        """
        Export threats to CCTNS (Crime and Criminal Tracking Network & Systems) format.

        This format is used by Indian law enforcement for cyber crime reporting.
        """
        if filepath is None:
            filepath = f"data/threats/cctns_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        # CCTNS format structure
        cctns_data = {
            "report_type": "CYBER_INCIDENT",
            "report_date": datetime.now().isoformat(),
            "reporting_agency": "RAKSHAK IoT Security System",
            "incidents": []
        }

        # Convert threats to CCTNS incident format
        with self._threats_lock:
            for threat in self.recent_threats:
                incident = {
                    "incident_id": threat.id,
                    "incident_date": threat.timestamp,
                    "incident_type": self._map_to_cctns_type(threat.type),
                    "severity": threat.severity.upper(),
                    "source_details": {
                        "ip_address": threat.source_ip,
                        "port": threat.source_port
                    },
                    "target_details": {
                        "ip_address": threat.target_ip,
                        "port": threat.target_port,
                        "device_name": threat.target_device
                    },
                    "attack_details": {
                        "protocol": threat.protocol,
                        "packet_count": threat.packets_count,
                        "duration_seconds": threat.duration_seconds,
                        "payload_sample": threat.payload[:100] if threat.payload else ""
                    },
                    "detection_method": threat.detected_by,
                    "status": "DETECTED_AND_MITIGATED"
                }
                cctns_data["incidents"].append(incident)

        # Save to file
        with open(filepath, "w") as f:
            json.dump(cctns_data, f, indent=2)

        logger.info(f"CCTNS export saved to {filepath}")
        return filepath

    def _map_to_cctns_type(self, threat_type: str) -> str:
        """Map internal threat type to CCTNS incident type."""
        mapping = {
            "port_scan": "NETWORK_SCANNING",
            "brute_force": "UNAUTHORIZED_ACCESS_ATTEMPT",
            "exploit_attempt": "SYSTEM_EXPLOITATION",
            "dos_attack": "DENIAL_OF_SERVICE",
            "malware": "MALWARE_ATTACK",
            "data_exfiltration": "DATA_THEFT",
            "unauthorized_access": "UNAUTHORIZED_ACCESS",
            "suspicious_traffic": "SUSPICIOUS_ACTIVITY"
        }
        return mapping.get(threat_type, "OTHER_CYBER_INCIDENT")

    def export_json(self, filepath: str = None) -> str:
        """Export all threats to JSON format."""
        if filepath is None:
            filepath = f"data/threats/threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        data = {
            "export_date": datetime.now().isoformat(),
            "statistics": self.stats,
            "threats": [t.to_dict() for t in self.recent_threats],
            "actions": [a.to_dict() for a in self.recent_actions]
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"JSON export saved to {filepath}")
        return filepath

    def log_device(
        self,
        ip: str,
        mac: str,
        hostname: str = "unknown",
        device_type: str = "unknown",
        os: str = "unknown",
        zone: str = "guest",
        enrollment_status: str = "unknown",
        risk_score: int = 0
    ):
        """
        Log or update a discovered device in the database with zone assignment.

        Args:
            ip: Device IP address
            mac: Device MAC address
            hostname: Device hostname
            device_type: Type of device
            os: Operating system
            zone: Security zone (guest, iot, main, mgmt, quarantine)
            enrollment_status: Enrollment status (unknown, pending, enrolled)
            risk_score: Risk score 0-100
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        device_id = f"DEV-{mac.replace(':', '').upper()}"
        timestamp = datetime.now().isoformat()

        try:
            # Check if device exists
            cursor.execute("SELECT id FROM devices WHERE ip = ? OR mac = ?", (ip, mac))
            existing = cursor.fetchone()

            if existing:
                # Update existing device
                cursor.execute("""
                    UPDATE devices
                    SET hostname = ?,
                        device_type = ?,
                        os = ?,
                        zone = ?,
                        enrollment_status = ?,
                        risk_score = ?,
                        last_seen = ?,
                        status = 'active'
                    WHERE ip = ? OR mac = ?
                """, (hostname, device_type, os, zone, enrollment_status,
                      risk_score, timestamp, ip, mac))
                logger.debug(f"Updated device {ip} in database (zone={zone})")
            else:
                # Insert new device
                cursor.execute("""
                    INSERT INTO devices (
                        id, ip, mac, hostname, device_type, os,
                        risk_score, first_seen, last_seen, status,
                        enrollment_status, zone
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (device_id, ip, mac, hostname, device_type, os,
                      risk_score, timestamp, timestamp, 'active',
                      enrollment_status, zone))
                logger.info(f"Added device {ip} to database (zone={zone}, status={enrollment_status})")

            conn.commit()

        except Exception as e:
            logger.error(f"Failed to log device {ip}: {e}")
            conn.rollback()
        finally:
            conn.close()

    def log_fingerprint(
        self,
        device_mac: str,
        device_ip: str,
        ja3_hash: str = None,
        ja3_confidence: float = 0.0,
        ja3_vendor: str = None,
        ja3_device_type: str = None,
        dhcp_option55: str = None,
        dhcp_confidence: float = 0.0,
        dhcp_os: str = None,
        tcp_signature: str = None,
        tcp_confidence: float = 0.0,
        tcp_os: str = None,
        dns_domains: str = None,
        dns_confidence: float = 0.0,
        dns_vendor: str = None,
        fused_vendor: str = None,
        fused_device_type: str = None,
        fused_os: str = None,
        overall_confidence: float = 0.0,
        identity_status: str = "UNKNOWN",
        fingerprint_complete: bool = False
    ):
        """
        Log or update device fingerprint data.

        Args:
            device_mac: Device MAC address
            device_ip: Device IP address
            ja3_hash: JA3 TLS fingerprint hash
            ja3_confidence: JA3 signal confidence
            ja3_vendor: Vendor identified by JA3
            ja3_device_type: Device type from JA3
            dhcp_option55: DHCP Option 55 signature
            dhcp_confidence: DHCP signal confidence
            dhcp_os: OS identified by DHCP
            tcp_signature: TCP/IP stack signature
            tcp_confidence: TCP/IP signal confidence
            tcp_os: OS identified by TCP/IP
            dns_domains: DNS domains queried (comma-separated)
            dns_confidence: DNS correlation confidence
            dns_vendor: Vendor identified by DNS
            fused_vendor: Final fused vendor identification
            fused_device_type: Final fused device type
            fused_os: Final fused OS
            overall_confidence: Overall identity confidence (0.0-1.0)
            identity_status: Identity status (UNKNOWN, CONFIRMED, SUSPICIOUS)
            fingerprint_complete: Whether fingerprinting is complete
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()

        try:
            # Check if fingerprint exists
            cursor.execute("SELECT device_mac FROM device_fingerprints WHERE device_mac = ?", (device_mac,))
            existing = cursor.fetchone()

            if existing:
                # Update existing fingerprint
                cursor.execute("""
                    UPDATE device_fingerprints
                    SET device_ip = ?,
                        ja3_hash = COALESCE(?, ja3_hash),
                        ja3_confidence = COALESCE(?, ja3_confidence),
                        ja3_vendor = COALESCE(?, ja3_vendor),
                        ja3_device_type = COALESCE(?, ja3_device_type),
                        dhcp_option55 = COALESCE(?, dhcp_option55),
                        dhcp_confidence = COALESCE(?, dhcp_confidence),
                        dhcp_os = COALESCE(?, dhcp_os),
                        tcp_signature = COALESCE(?, tcp_signature),
                        tcp_confidence = COALESCE(?, tcp_confidence),
                        tcp_os = COALESCE(?, tcp_os),
                        dns_domains = COALESCE(?, dns_domains),
                        dns_confidence = COALESCE(?, dns_confidence),
                        dns_vendor = COALESCE(?, dns_vendor),
                        fused_vendor = COALESCE(?, fused_vendor),
                        fused_device_type = COALESCE(?, fused_device_type),
                        fused_os = COALESCE(?, fused_os),
                        overall_confidence = ?,
                        identity_status = ?,
                        last_updated = ?,
                        fingerprint_complete = ?
                    WHERE device_mac = ?
                """, (device_ip, ja3_hash, ja3_confidence, ja3_vendor, ja3_device_type,
                      dhcp_option55, dhcp_confidence, dhcp_os,
                      tcp_signature, tcp_confidence, tcp_os,
                      dns_domains, dns_confidence, dns_vendor,
                      fused_vendor, fused_device_type, fused_os,
                      overall_confidence, identity_status, timestamp,
                      1 if fingerprint_complete else 0, device_mac))
                logger.debug(f"Updated fingerprint for {device_mac} (confidence={overall_confidence:.2f})")
            else:
                # Insert new fingerprint
                cursor.execute("""
                    INSERT INTO device_fingerprints (
                        device_mac, device_ip, ja3_hash, ja3_confidence, ja3_vendor, ja3_device_type,
                        dhcp_option55, dhcp_confidence, dhcp_os,
                        tcp_signature, tcp_confidence, tcp_os,
                        dns_domains, dns_confidence, dns_vendor,
                        fused_vendor, fused_device_type, fused_os,
                        overall_confidence, identity_status,
                        first_seen, last_updated, fingerprint_complete
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (device_mac, device_ip, ja3_hash, ja3_confidence, ja3_vendor, ja3_device_type,
                      dhcp_option55, dhcp_confidence, dhcp_os,
                      tcp_signature, tcp_confidence, tcp_os,
                      dns_domains, dns_confidence, dns_vendor,
                      fused_vendor, fused_device_type, fused_os,
                      overall_confidence, identity_status,
                      timestamp, timestamp, 1 if fingerprint_complete else 0))
                logger.info(f"Created fingerprint for {device_mac} (confidence={overall_confidence:.2f})")

            conn.commit()

        except Exception as e:
            logger.error(f"Failed to log fingerprint for {device_mac}: {e}")
            conn.rollback()
        finally:
            conn.close()

    def update_device_confidence(
        self,
        device_ip: str,
        device_mac: str,
        confidence_score: float,
        state: str = "FINGERPRINTING",
        signals_collected: int = 0,
        drift_score: float = 0.0,
        anomaly_count: int = 0,
        re_evaluation_needed: bool = False
    ):
        """
        Update device confidence tracking.

        Args:
            device_ip: Device IP address
            device_mac: Device MAC address
            confidence_score: Overall confidence score (0.0-1.0)
            state: Device state (DISCOVERED, FINGERPRINTING, IDENTIFIED, TRUSTED, SUSPICIOUS)
            signals_collected: Number of fingerprint signals collected
            drift_score: Identity drift score
            anomaly_count: Number of anomalies detected
            re_evaluation_needed: Whether re-evaluation is needed
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()

        try:
            cursor.execute("SELECT device_ip FROM device_confidence WHERE device_ip = ?", (device_ip,))
            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE device_confidence
                    SET device_mac = ?,
                        confidence_score = ?,
                        state = ?,
                        signals_collected = ?,
                        drift_score = ?,
                        anomaly_count = ?,
                        last_confidence_update = ?,
                        re_evaluation_needed = ?
                    WHERE device_ip = ?
                """, (device_mac, confidence_score, state, signals_collected,
                      drift_score, anomaly_count, timestamp,
                      1 if re_evaluation_needed else 0, device_ip))
            else:
                cursor.execute("""
                    INSERT INTO device_confidence (
                        device_ip, device_mac, confidence_score, state,
                        signals_collected, drift_score, anomaly_count,
                        last_confidence_update, re_evaluation_needed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (device_ip, device_mac, confidence_score, state,
                      signals_collected, drift_score, anomaly_count,
                      timestamp, 1 if re_evaluation_needed else 0))

            conn.commit()
            logger.debug(f"Updated confidence for {device_ip}: {confidence_score:.2f} ({state})")

        except Exception as e:
            logger.error(f"Failed to update confidence for {device_ip}: {e}")
            conn.rollback()
        finally:
            conn.close()

    def log_cloud_endpoint(
        self,
        device_ip: str,
        device_mac: str,
        domain: str,
        resolved_ip: str = None,
        vendor: str = None
    ):
        """
        Log a cloud endpoint (DNS query) from a device.

        Args:
            device_ip: Device IP address
            device_mac: Device MAC address
            domain: DNS domain queried
            resolved_ip: Resolved IP address
            vendor: Identified vendor from domain
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()

        try:
            # Check if endpoint already logged for this device
            cursor.execute("""
                SELECT id, query_count FROM device_cloud_endpoints
                WHERE device_mac = ? AND domain = ?
            """, (device_mac, domain))
            existing = cursor.fetchone()

            if existing:
                # Update query count and last seen
                cursor.execute("""
                    UPDATE device_cloud_endpoints
                    SET last_seen = ?,
                        query_count = ?,
                        resolved_ip = COALESCE(?, resolved_ip),
                        vendor = COALESCE(?, vendor)
                    WHERE id = ?
                """, (timestamp, existing[1] + 1, resolved_ip, vendor, existing[0]))
            else:
                # Insert new endpoint
                cursor.execute("""
                    INSERT INTO device_cloud_endpoints (
                        device_ip, device_mac, domain, resolved_ip, vendor,
                        first_seen, last_seen, query_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (device_ip, device_mac, domain, resolved_ip, vendor,
                      timestamp, timestamp, 1))

            conn.commit()

        except Exception as e:
            logger.error(f"Failed to log cloud endpoint for {device_ip}: {e}")
            conn.rollback()
        finally:
            conn.close()

    def log_fingerprint_signal(
        self,
        device_mac: str,
        signal_type: str,
        signal_value: str,
        confidence: float
    ):
        """
        Log an individual fingerprint signal to history.

        Args:
            device_mac: Device MAC address
            signal_type: Signal type (tls_ja3, dhcp_option55, tcp_stack, dns_query)
            signal_value: Signal value
            confidence: Signal confidence
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()

        try:
            cursor.execute("""
                INSERT INTO fingerprint_signal_history (
                    device_mac, signal_type, signal_value, confidence, captured_at
                ) VALUES (?, ?, ?, ?, ?)
            """, (device_mac, signal_type, signal_value, confidence, timestamp))

            conn.commit()
            logger.debug(f"Logged {signal_type} signal for {device_mac}")

        except Exception as e:
            logger.error(f"Failed to log signal for {device_mac}: {e}")
            conn.rollback()
        finally:
            conn.close()


# Simulated threat generator for testing
class SimulatedThreatGenerator:
    """Generate simulated threats for testing."""

    ATTACK_TYPES = [
        ("port_scan", "medium", "Network port scanning detected"),
        ("brute_force", "high", "SSH brute force attack"),
        ("exploit_attempt", "critical", "Known CVE exploit attempt"),
        ("dos_attack", "high", "Denial of service attack"),
        ("suspicious_traffic", "low", "Unusual traffic pattern")
    ]

    def __init__(self, config: dict, real_devices: list = None):
        self.config = config
        self.fake_devices = config.get("simulation", {}).get("fake_devices", [])
        self.real_devices = real_devices or []

    def generate_threat(self, attack_type: str = None) -> dict:
        """
        Generate a random simulated threat.

        Args:
            attack_type: Optional specific attack type to generate.
                         One of: port_scan, brute_force, exploit_attempt, dos_attack, suspicious_traffic
        """
        import random

        # Use specific attack type if provided, otherwise random
        if attack_type:
            attack = next((a for a in self.ATTACK_TYPES if a[0] == attack_type), random.choice(self.ATTACK_TYPES))
        else:
            attack = random.choice(self.ATTACK_TYPES)

        # Prefer real devices over fake devices
        if self.real_devices:
            target = random.choice(self.real_devices)
            target_ip = target.get("ip", target.get("ip_address", "192.168.1.100"))
            target_name = target.get("hostname", target.get("name", "Unknown Device"))
        elif self.fake_devices:
            target = random.choice(self.fake_devices)
            target_ip = target.get("ip", "192.168.1.100")
            target_name = target.get("name", "Unknown Device")
        else:
            target_ip = "192.168.1.100"
            target_name = "Unknown Device"

        # For simulated threats, source_ip is the "attacker"
        # In real scenarios, this would be an external IP
        # For testing isolation, we use the target device IP as source
        # so isolation actually blocks the device
        return {
            "type": attack[0],
            "severity": attack[1],
            "description": attack[2],
            "source_ip": target_ip,  # Use device IP so isolation works on real devices
            "source_port": random.randint(1024, 65535),
            "target_ip": target_ip,
            "target_device": target_name,
            "target_port": random.choice([22, 23, 80, 443, 8080, 1883, 5540]),
            "protocol": random.choice(["tcp", "udp"]),
            "packets_count": random.randint(10, 1000),
            "duration_seconds": random.uniform(0.5, 30.0)
        }
