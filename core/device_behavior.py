#!/usr/bin/env python3
"""
RAKSHAK Device Behavior Baseline Module
========================================

Tracks normal device behavior and detects anomalies.

Features:
- Learning period for baseline establishment
- Protocol usage tracking
- Port access monitoring
- Internal peer relationship mapping
- Anomaly detection

Author: Team RAKSHAK
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass

from loguru import logger


@dataclass
class DeviceProfile:
    """Device behavior profile"""
    device_ip: str
    device_mac: Optional[str]
    baseline_start: datetime
    total_flows: int = 0
    status: str = "learning"  # learning, active
    protocols_used: Set[str] = None
    common_dst_ports: Set[int] = None
    internal_peers: Set[str] = None
    avg_bytes_per_flow: float = 0.0
    active_hours: Set[int] = None

    def __post_init__(self):
        if self.protocols_used is None:
            self.protocols_used = set()
        if self.common_dst_ports is None:
            self.common_dst_ports = set()
        if self.internal_peers is None:
            self.internal_peers = set()
        if self.active_hours is None:
            self.active_hours = set()

    def is_learning(self) -> bool:
        """Check if still in learning period"""
        return self.status == "learning"


class DeviceBehaviorBaseline:
    """
    Track device behavior baselines for anomaly detection.

    Establishes normal behavior patterns during a learning period,
    then detects deviations that may indicate compromise.
    """

    def __init__(self, db_path: str, learning_period_hours: int = 24):
        """
        Initialize device behavior baseline tracker.

        Args:
            db_path: Path to SQLite database
            learning_period_hours: Hours to learn baseline (default: 24)
        """
        self.db_path = db_path
        self.learning_period = timedelta(hours=learning_period_hours)
        self.profiles: Dict[str, DeviceProfile] = {}

        logger.info(f"DeviceBehaviorBaseline initialized (learning period: {learning_period_hours}h)")

    def update_profile(self, device_ip: str, flow_data: dict) -> Optional[List[dict]]:
        """
        Update device behavior profile with new flow data.

        Args:
            device_ip: Device IP address
            flow_data: Flow feature dictionary

        Returns:
            List of anomalies detected, or None
        """
        # Get or create profile
        if device_ip not in self.profiles:
            profile = self._load_profile_from_db(device_ip)
            if not profile:
                profile = self._create_new_profile(device_ip)
            self.profiles[device_ip] = profile
        else:
            profile = self.profiles[device_ip]

        # Update profile with flow data
        profile.total_flows += 1
        profile.protocols_used.add(flow_data.get('protocol', 'unknown'))
        profile.common_dst_ports.add(flow_data.get('dst_port', 0))

        # Track internal peers (dst_ip)
        dst_ip = flow_data.get('dst_ip')
        if dst_ip and self._is_internal_ip(dst_ip):
            profile.internal_peers.add(dst_ip)

        # Track active hours
        current_hour = datetime.now().hour
        profile.active_hours.add(current_hour)

        # Update average bytes per flow
        flow_bytes = flow_data.get('total_length_fwd_packets', 0) + flow_data.get('total_length_bwd_packets', 0)
        profile.avg_bytes_per_flow = (
            (profile.avg_bytes_per_flow * (profile.total_flows - 1) + flow_bytes) / profile.total_flows
        )

        # Check if learning period is complete
        if profile.is_learning():
            time_elapsed = datetime.now() - profile.baseline_start
            if time_elapsed >= self.learning_period and profile.total_flows >= 50:
                profile.status = "active"
                logger.info(f"Device {device_ip} baseline learning complete "
                           f"({profile.total_flows} flows, {time_elapsed.total_seconds()/3600:.1f}h)")

        # Save profile to database
        self._save_profile_to_db(profile)

        # Detect anomalies if not learning
        if not profile.is_learning():
            anomalies = self._detect_anomalies(profile, flow_data)
            if anomalies:
                self._log_anomalies(device_ip, anomalies)
                return anomalies

        return None

    def _create_new_profile(self, device_ip: str) -> DeviceProfile:
        """Create new device profile"""
        profile = DeviceProfile(
            device_ip=device_ip,
            device_mac=None,  # TODO: Get from device table
            baseline_start=datetime.now(),
            status="learning"
        )
        logger.info(f"Created new behavior profile for {device_ip}")
        return profile

    def _load_profile_from_db(self, device_ip: str) -> Optional[DeviceProfile]:
        """Load device profile from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT device_mac, baseline_start, total_flows, status,
                       protocols_used, common_dst_ports, internal_peers,
                       avg_bytes_per_flow, active_hours
                FROM device_baselines
                WHERE device_ip = ?
            """, (device_ip,))

            row = cursor.fetchone()
            conn.close()

            if row:
                profile = DeviceProfile(
                    device_ip=device_ip,
                    device_mac=row[0],
                    baseline_start=datetime.fromisoformat(row[1]),
                    total_flows=row[2],
                    status=row[3],
                    protocols_used=set(json.loads(row[4] or "[]")),
                    common_dst_ports=set(json.loads(row[5] or "[]")),
                    internal_peers=set(json.loads(row[6] or "[]")),
                    avg_bytes_per_flow=row[7] or 0.0,
                    active_hours=set(json.loads(row[8] or "[]"))
                )
                logger.debug(f"Loaded baseline for {device_ip} from database")
                return profile

            return None

        except Exception as e:
            logger.error(f"Failed to load profile from database: {e}")
            return None

    def _save_profile_to_db(self, profile: DeviceProfile):
        """Save device profile to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO device_baselines
                (device_ip, device_mac, baseline_start, total_flows, status,
                 protocols_used, common_dst_ports, internal_peers,
                 avg_bytes_per_flow, active_hours, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.device_ip,
                profile.device_mac,
                profile.baseline_start.isoformat(),
                profile.total_flows,
                profile.status,
                json.dumps(list(profile.protocols_used)),
                json.dumps(list(profile.common_dst_ports)),
                json.dumps(list(profile.internal_peers)),
                profile.avg_bytes_per_flow,
                json.dumps(list(profile.active_hours)),
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Failed to save profile to database: {e}")

    def _detect_anomalies(self, profile: DeviceProfile, flow_data: dict) -> Optional[List[dict]]:
        """
        Detect behavioral anomalies.

        Anomaly types:
        - NEW_PROTOCOL: Device using new protocol
        - SUSPICIOUS_PORT: Access to suspicious ports (SSH, Telnet, RDP)
        - NEW_INTERNAL_PEER: Device contacting new internal device
        - ABNORMAL_VOLUME: Unusual traffic volume
        """
        anomalies = []

        # New protocol
        protocol = flow_data.get('protocol', 'unknown')
        if protocol not in profile.protocols_used:
            anomalies.append({
                'type': 'NEW_PROTOCOL',
                'severity': 'medium',
                'description': f"Device using new protocol: {protocol}",
                'deviation_score': 0.6
            })

        # Suspicious ports (SSH, Telnet, RDP, SMB)
        dst_port = flow_data.get('dst_port', 0)
        suspicious_ports = {22: 'SSH', 23: 'Telnet', 3389: 'RDP', 445: 'SMB', 135: 'RPC'}

        if dst_port in suspicious_ports:
            anomalies.append({
                'type': 'SUSPICIOUS_PORT',
                'severity': 'high',
                'description': f"Device initiating {suspicious_ports[dst_port]} connection to port {dst_port}",
                'deviation_score': 0.8
            })

        # New internal peer (potential lateral movement)
        dst_ip = flow_data.get('dst_ip')
        if dst_ip and self._is_internal_ip(dst_ip):
            if dst_ip not in profile.internal_peers:
                anomalies.append({
                    'type': 'NEW_INTERNAL_PEER',
                    'severity': 'high',
                    'description': f"Device contacting new internal device: {dst_ip}",
                    'deviation_score': 0.7
                })

        # Abnormal traffic volume
        flow_bytes = flow_data.get('total_length_fwd_packets', 0) + flow_data.get('total_length_bwd_packets', 0)
        if profile.avg_bytes_per_flow > 0:
            deviation_ratio = flow_bytes / profile.avg_bytes_per_flow
            if deviation_ratio > 10:  # 10x normal volume
                anomalies.append({
                    'type': 'ABNORMAL_VOLUME',
                    'severity': 'medium',
                    'description': f"Abnormal traffic volume: {deviation_ratio:.1f}x normal",
                    'deviation_score': min(0.9, 0.5 + (deviation_ratio / 20))
                })

        return anomalies if anomalies else None

    def _log_anomalies(self, device_ip: str, anomalies: List[dict]):
        """Log anomalies to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for anomaly in anomalies:
                anomaly_id = f"ANM-{datetime.now().strftime('%Y%m%d%H%M%S')}-{device_ip}"

                cursor.execute("""
                    INSERT INTO device_anomalies
                    (id, timestamp, device_ip, anomaly_type, severity,
                     description, deviation_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    anomaly_id,
                    datetime.now().isoformat(),
                    device_ip,
                    anomaly['type'],
                    anomaly['severity'],
                    anomaly['description'],
                    anomaly['deviation_score']
                ))

                logger.warning(f"ANOMALY: {device_ip} - {anomaly['description']}")

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Failed to log anomalies: {e}")

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal (RFC1918)"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True

            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True

            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True

            return False

        except:
            return False

    def get_profile(self, device_ip: str) -> Optional[DeviceProfile]:
        """Get device profile"""
        if device_ip in self.profiles:
            return self.profiles[device_ip]

        return self._load_profile_from_db(device_ip)

    def get_all_anomalies(self, device_ip: Optional[str] = None, limit: int = 100) -> List[dict]:
        """Get recent anomalies"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            if device_ip:
                cursor.execute("""
                    SELECT id, timestamp, device_ip, anomaly_type, severity,
                           description, deviation_score
                    FROM device_anomalies
                    WHERE device_ip = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (device_ip, limit))
            else:
                cursor.execute("""
                    SELECT id, timestamp, device_ip, anomaly_type, severity,
                           description, deviation_score
                    FROM device_anomalies
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))

            anomalies = []
            for row in cursor.fetchall():
                anomalies.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'device_ip': row[2],
                    'anomaly_type': row[3],
                    'severity': row[4],
                    'description': row[5],
                    'deviation_score': row[6]
                })

            conn.close()
            return anomalies

        except Exception as e:
            logger.error(f"Failed to get anomalies: {e}")
            return []

    def calculate_identity_drift(
        self,
        device_ip: str,
        device_mac: str,
        current_fingerprint: dict
    ) -> Optional[dict]:
        """
        Calculate identity drift score for a device.

        Compares current behavior/fingerprints with baseline to detect identity changes
        that may indicate device compromise or replacement.

        Args:
            device_ip: Device IP address
            device_mac: Device MAC address
            current_fingerprint: Current fingerprint data from fingerprinting module

        Returns:
            Drift detection result dict or None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get baseline fingerprint
            cursor.execute("""
                SELECT ja3_hash, dhcp_option55, tcp_signature, dns_domains,
                       fused_vendor, fused_device_type, fused_os
                FROM device_fingerprints
                WHERE device_mac = ?
            """, (device_mac,))

            baseline_row = cursor.fetchone()
            if not baseline_row:
                logger.debug(f"No baseline fingerprint for {device_ip}, skipping drift detection")
                conn.close()
                return None

            baseline = {
                'ja3_hash': baseline_row[0],
                'dhcp_option55': baseline_row[1],
                'tcp_signature': baseline_row[2],
                'dns_domains': baseline_row[3],
                'fused_vendor': baseline_row[4],
                'fused_device_type': baseline_row[5],
                'fused_os': baseline_row[6]
            }

            # Get baseline behavior profile
            profile = self.get_profile(device_ip)
            if not profile or profile.is_learning():
                conn.close()
                return None

            # Calculate drift components
            protocol_drift = self._calculate_protocol_drift(profile, current_fingerprint)
            port_drift = self._calculate_port_drift(profile, current_fingerprint)
            volume_drift = self._calculate_volume_drift(profile, current_fingerprint)
            temporal_drift = self._calculate_temporal_drift(profile, current_fingerprint)
            peer_drift = self._calculate_peer_drift(profile, current_fingerprint)

            # Weighted drift score
            drift_score = (
                protocol_drift * 0.30 +
                port_drift * 0.25 +
                volume_drift * 0.20 +
                temporal_drift * 0.15 +
                peer_drift * 0.10
            )

            # Fingerprint changes (critical signals)
            fingerprint_changed = False
            changed_signals = []

            if current_fingerprint.get('ja3_hash') and current_fingerprint['ja3_hash'] != baseline['ja3_hash']:
                fingerprint_changed = True
                changed_signals.append('ja3_hash')
                drift_score += 0.3  # Major drift increase for TLS change

            if current_fingerprint.get('dhcp_option55') and current_fingerprint['dhcp_option55'] != baseline['dhcp_option55']:
                fingerprint_changed = True
                changed_signals.append('dhcp_option55')
                drift_score += 0.2

            if current_fingerprint.get('tcp_signature') and current_fingerprint['tcp_signature'] != baseline['tcp_signature']:
                fingerprint_changed = True
                changed_signals.append('tcp_signature')
                drift_score += 0.2

            # Cap at 1.0
            drift_score = min(drift_score, 1.0)

            # Determine severity
            if drift_score >= 0.8:
                severity = "critical"
                drift_type = "CONFIRMED_COMPROMISE"
            elif drift_score >= 0.5:
                severity = "high"
                drift_type = "LIKELY_COMPROMISE"
            elif drift_score >= 0.2:
                severity = "medium"
                drift_type = "SUSPICIOUS_CHANGE"
            else:
                severity = "low"
                drift_type = "MINOR_DEVIATION"

            result = {
                'drift_score': drift_score,
                'severity': severity,
                'drift_type': drift_type,
                'fingerprint_changed': fingerprint_changed,
                'changed_signals': changed_signals,
                'components': {
                    'protocol_drift': protocol_drift,
                    'port_drift': port_drift,
                    'volume_drift': volume_drift,
                    'temporal_drift': temporal_drift,
                    'peer_drift': peer_drift
                },
                'baseline': baseline,
                'current': current_fingerprint
            }

            # Log if significant drift
            if drift_score >= 0.2:
                self._log_identity_drift(device_ip, device_mac, result)
                logger.warning(
                    f"IDENTITY DRIFT: {device_ip} | Score={drift_score:.2f} | "
                    f"Type={drift_type} | Signals={changed_signals}"
                )

            # Update device_confidence table with drift score
            cursor.execute("""
                UPDATE device_confidence
                SET drift_score = ?,
                    re_evaluation_needed = ?
                WHERE device_ip = ?
            """, (drift_score, 1 if drift_score >= 0.5 else 0, device_ip))

            conn.commit()
            conn.close()

            return result

        except Exception as e:
            logger.error(f"Failed to calculate identity drift for {device_ip}: {e}")
            return None

    def _calculate_protocol_drift(self, profile: DeviceProfile, current: dict) -> float:
        """Calculate protocol usage drift."""
        current_protocols = set(current.get('protocols_used', []))
        baseline_protocols = profile.protocols_used

        if not baseline_protocols:
            return 0.0

        # Protocols in current but not in baseline
        new_protocols = current_protocols - baseline_protocols

        # Drift = ratio of new protocols
        drift = len(new_protocols) / len(baseline_protocols | current_protocols)
        return min(drift, 1.0)

    def _calculate_port_drift(self, profile: DeviceProfile, current: dict) -> float:
        """Calculate destination port drift."""
        current_ports = set(current.get('dst_ports', []))
        baseline_ports = profile.common_dst_ports

        if not baseline_ports:
            return 0.0

        # Ports in current but not in baseline
        new_ports = current_ports - baseline_ports

        # Drift = ratio of new ports
        drift = len(new_ports) / len(baseline_ports | current_ports)
        return min(drift, 1.0)

    def _calculate_volume_drift(self, profile: DeviceProfile, current: dict) -> float:
        """Calculate traffic volume drift."""
        current_avg = current.get('avg_bytes_per_flow', 0)
        baseline_avg = profile.avg_bytes_per_flow

        if baseline_avg == 0:
            return 0.0

        # Volume deviation ratio
        ratio = abs(current_avg - baseline_avg) / baseline_avg

        # Normalize to 0-1 (consider 5x change as max drift)
        drift = min(ratio / 5.0, 1.0)
        return drift

    def _calculate_temporal_drift(self, profile: DeviceProfile, current: dict) -> float:
        """Calculate temporal pattern drift (active hours)."""
        current_hours = set(current.get('active_hours', []))
        baseline_hours = profile.active_hours

        if not baseline_hours:
            return 0.0

        # Hours active in current but not baseline
        new_hours = current_hours - baseline_hours

        # Drift = ratio of new active hours
        drift = len(new_hours) / 24.0  # Out of 24 hours
        return min(drift, 1.0)

    def _calculate_peer_drift(self, profile: DeviceProfile, current: dict) -> float:
        """Calculate internal peer relationship drift."""
        current_peers = set(current.get('internal_peers', []))
        baseline_peers = profile.internal_peers

        if not baseline_peers:
            return 0.0

        # New peers not in baseline
        new_peers = current_peers - baseline_peers

        # Drift = ratio of new peers (capped at 3 new peers = max)
        drift = min(len(new_peers) / 3.0, 1.0)
        return drift

    def _log_identity_drift(self, device_ip: str, device_mac: str, drift_result: dict):
        """Log identity drift event to database."""
        try:
            import uuid
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            event_id = f"drift-{uuid.uuid4().hex[:8]}"
            timestamp = datetime.now().isoformat()

            baseline = drift_result.get('baseline', {})
            current = drift_result.get('current', {})

            cursor.execute("""
                INSERT INTO identity_drift_events (
                    id, timestamp, device_ip, device_mac, drift_score, drift_type,
                    severity, baseline_protocols, current_protocols,
                    baseline_ports, current_ports, action_taken
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id,
                timestamp,
                device_ip,
                device_mac,
                drift_result['drift_score'],
                drift_result['drift_type'],
                drift_result['severity'],
                json.dumps(list(baseline.get('protocols_used', []))),
                json.dumps(current.get('protocols_used', [])),
                json.dumps(list(baseline.get('common_dst_ports', []))),
                json.dumps(current.get('dst_ports', [])),
                "re_evaluation" if drift_result['drift_score'] >= 0.5 else "logged"
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Failed to log identity drift event: {e}")

    def get_drift_events(self, device_ip: Optional[str] = None, limit: int = 50) -> List[dict]:
        """Get recent identity drift events."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            if device_ip:
                cursor.execute("""
                    SELECT id, timestamp, device_ip, drift_score, drift_type,
                           severity, action_taken
                    FROM identity_drift_events
                    WHERE device_ip = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (device_ip, limit))
            else:
                cursor.execute("""
                    SELECT id, timestamp, device_ip, drift_score, drift_type,
                           severity, action_taken
                    FROM identity_drift_events
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))

            events = []
            for row in cursor.fetchall():
                events.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'device_ip': row[2],
                    'drift_score': row[3],
                    'drift_type': row[4],
                    'severity': row[5],
                    'action_taken': row[6]
                })

            conn.close()
            return events

        except Exception as e:
            logger.error(f"Failed to get drift events: {e}")
            return []
