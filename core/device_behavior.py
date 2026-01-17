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
