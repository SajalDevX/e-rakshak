#!/usr/bin/env python3
"""
RAKSHAK Attack Chain Tracker
=============================

Graph-based tracking of lateral movement and attack chains.

Features:
- Directed graph of compromised devices
- Chain detection and analysis
- Temporal attack sequence tracking
- Automatic chain isolation recommendations

Author: Team RAKSHAK
"""

import sqlite3
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from collections import defaultdict

from loguru import logger


class AttackChainTracker:
    """
    Track and analyze attack chains using graph-based approach.

    Models lateral movement as a directed graph where:
    - Nodes = devices (IP addresses)
    - Edges = compromise relationships (attacker -> victim)
    """

    def __init__(self, db_path: str, chain_timeout_hours: int = 24):
        """
        Initialize attack chain tracker.

        Args:
            db_path: Path to SQLite database
            chain_timeout_hours: Hours before chain is considered inactive
        """
        self.db_path = db_path
        self.timeout = timedelta(hours=chain_timeout_hours)

        # Graph: adjacency list (source_ip -> list of target_ips)
        self.graph: Dict[str, List[str]] = defaultdict(list)

        # Chain metadata
        self.chains: Dict[str, dict] = {}

        # Load active chains from database
        self._load_active_chains()

        logger.info(f"AttackChainTracker initialized (timeout: {chain_timeout_hours}h)")

    def record_compromise(self, source_ip: str, target_ip: str,
                         attack_type: str, severity: str,
                         confidence: float) -> Optional[dict]:
        """
        Record a compromise and detect attack chains.

        Args:
            source_ip: Attacker/source IP
            target_ip: Victim/target IP
            attack_type: Type of attack
            severity: Severity level
            confidence: Detection confidence (0.0-1.0)

        Returns:
            Chain information if chain detected, None otherwise
        """
        logger.info(f"Recording compromise: {source_ip} -> {target_ip} ({attack_type})")

        # Add edge to graph
        if target_ip not in self.graph[source_ip]:
            self.graph[source_ip].append(target_ip)

        # Find or create chain
        chain_id = self._find_or_create_chain(source_ip, target_ip)

        # Update chain metadata
        chain_info = self._analyze_chain(chain_id, source_ip, target_ip, attack_type, severity)

        # Alert if significant chain detected
        if chain_info and chain_info['chain_length'] >= 2:
            logger.critical(
                f"ATTACK CHAIN DETECTED: Chain ID {chain_id} | "
                f"Length: {chain_info['chain_length']} | "
                f"Root: {chain_info['root_device_ip']} | "
                f"Devices: {chain_info['compromised_devices']}"
            )

            chain_info['elevated_severity'] = 'critical'
            chain_info['recommended_action'] = 'ISOLATE_ENTIRE_CHAIN'

            # Save to database
            self._save_chain_to_db(chain_info)

            return chain_info

        return None

    def _find_or_create_chain(self, source_ip: str, target_ip: str) -> str:
        """
        Find existing chain or create new one.

        Args:
            source_ip: Source IP
            target_ip: Target IP

        Returns:
            Chain ID
        """
        # Check if source_ip is already in a chain
        for chain_id, chain_data in self.chains.items():
            if source_ip in chain_data['devices']:
                # Extend existing chain
                if target_ip not in chain_data['devices']:
                    chain_data['devices'].add(target_ip)
                    chain_data['last_activity'] = datetime.now()
                return chain_id

        # Check if target_ip is already a root of another chain
        for chain_id, chain_data in self.chains.items():
            if target_ip == chain_data['root_device_ip']:
                # Merge chains
                if source_ip not in chain_data['devices']:
                    chain_data['devices'].add(source_ip)
                    chain_data['last_activity'] = datetime.now()
                return chain_id

        # Create new chain
        chain_id = f"CHAIN-{uuid.uuid4().hex[:8].upper()}"
        self.chains[chain_id] = {
            'chain_id': chain_id,
            'root_device_ip': source_ip,
            'devices': {source_ip, target_ip},
            'first_seen': datetime.now(),
            'last_activity': datetime.now(),
            'is_active': True
        }

        logger.info(f"Created new attack chain: {chain_id}")
        return chain_id

    def _analyze_chain(self, chain_id: str, source_ip: str, target_ip: str,
                       attack_type: str, severity: str) -> dict:
        """Analyze chain and compute metrics"""
        chain_data = self.chains[chain_id]

        # Get all devices in chain
        compromised_devices = list(chain_data['devices'])

        # Compute chain length (number of hops)
        chain_length = self._compute_chain_depth(chain_data['root_device_ip'])

        # Build attack sequence
        attack_sequence = self._build_attack_sequence(chain_id)

        # Determine severity
        if chain_length >= 3:
            final_severity = 'critical'
        elif chain_length == 2:
            final_severity = 'high'
        else:
            final_severity = severity

        chain_info = {
            'chain_id': chain_id,
            'root_device_ip': chain_data['root_device_ip'],
            'compromised_devices': compromised_devices,
            'chain_length': chain_length,
            'attack_sequence': attack_sequence,
            'severity': final_severity,
            'first_seen': chain_data['first_seen'].isoformat(),
            'last_activity': chain_data['last_activity'].isoformat(),
            'is_active': True
        }

        self.chains[chain_id].update(chain_info)

        return chain_info

    def _compute_chain_depth(self, root_ip: str) -> int:
        """
        Compute maximum depth (number of hops) from root.

        Uses BFS to find longest path in directed graph.
        """
        if root_ip not in self.graph:
            return 1

        max_depth = 1
        visited = set()
        queue = [(root_ip, 1)]

        while queue:
            current_ip, depth = queue.pop(0)
            if current_ip in visited:
                continue

            visited.add(current_ip)
            max_depth = max(max_depth, depth)

            # Add children to queue
            for child_ip in self.graph.get(current_ip, []):
                if child_ip not in visited:
                    queue.append((child_ip, depth + 1))

        return max_depth

    def _build_attack_sequence(self, chain_id: str) -> List[dict]:
        """Build chronological attack sequence"""
        # Simplified version - returns edges in graph
        chain_data = self.chains[chain_id]
        root_ip = chain_data['root_device_ip']

        sequence = []

        def traverse(node, depth=0):
            for target in self.graph.get(node, []):
                if target in chain_data['devices']:
                    sequence.append({
                        'source': node,
                        'target': target,
                        'hop': depth + 1
                    })
                    traverse(target, depth + 1)

        traverse(root_ip)
        return sequence

    def get_dependent_devices(self, device_ip: str) -> Set[str]:
        """
        Get all devices compromised downstream from this device.

        Args:
            device_ip: Device IP to check

        Returns:
            Set of downstream device IPs
        """
        if device_ip not in self.graph:
            return set()

        descendants = set()
        visited = set()
        queue = [device_ip]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue

            visited.add(current)

            for child in self.graph.get(current, []):
                descendants.add(child)
                queue.append(child)

        return descendants

    def get_chain_for_device(self, device_ip: str) -> Optional[dict]:
        """Get chain information for a device"""
        for chain_id, chain_data in self.chains.items():
            if device_ip in chain_data.get('devices', set()):
                return chain_data

        return None

    def _save_chain_to_db(self, chain_info: dict):
        """Save attack chain to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO attack_chains
                (chain_id, root_device_ip, compromised_devices, attack_sequence,
                 first_seen, last_activity, chain_length, severity, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                chain_info['chain_id'],
                chain_info['root_device_ip'],
                json.dumps(chain_info['compromised_devices']),
                json.dumps(chain_info['attack_sequence']),
                chain_info['first_seen'],
                chain_info['last_activity'],
                chain_info['chain_length'],
                chain_info['severity'],
                1 if chain_info['is_active'] else 0
            ))

            conn.commit()
            conn.close()

            logger.debug(f"Saved attack chain {chain_info['chain_id']} to database")

        except Exception as e:
            logger.error(f"Failed to save attack chain: {e}")

    def _load_active_chains(self):
        """Load active attack chains from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT chain_id, root_device_ip, compromised_devices,
                       attack_sequence, first_seen, last_activity,
                       chain_length, severity
                FROM attack_chains
                WHERE is_active = 1
            """)

            for row in cursor.fetchall():
                chain_id = row[0]
                compromised_devices = json.loads(row[2])
                attack_sequence = json.loads(row[3])

                # Reconstruct graph
                for edge in attack_sequence:
                    source = edge['source']
                    target = edge['target']
                    if target not in self.graph[source]:
                        self.graph[source].append(target)

                # Reconstruct chain metadata
                self.chains[chain_id] = {
                    'chain_id': chain_id,
                    'root_device_ip': row[1],
                    'devices': set(compromised_devices),
                    'attack_sequence': attack_sequence,
                    'first_seen': datetime.fromisoformat(row[4]),
                    'last_activity': datetime.fromisoformat(row[5]),
                    'chain_length': row[6],
                    'severity': row[7],
                    'is_active': True
                }

            conn.close()

            if self.chains:
                logger.info(f"Loaded {len(self.chains)} active attack chains from database")

        except Exception as e:
            logger.error(f"Failed to load attack chains: {e}")

    def expire_old_chains(self) -> int:
        """Mark inactive chains as expired"""
        current_time = datetime.now()
        expired_count = 0

        for chain_id, chain_data in list(self.chains.items()):
            if current_time - chain_data['last_activity'] > self.timeout:
                chain_data['is_active'] = False

                # Update database
                try:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE attack_chains
                        SET is_active = 0
                        WHERE chain_id = ?
                    """, (chain_id,))
                    conn.commit()
                    conn.close()

                    expired_count += 1
                    logger.info(f"Expired attack chain {chain_id}")

                except Exception as e:
                    logger.error(f"Failed to expire chain: {e}")

        return expired_count

    def get_active_chains(self) -> List[dict]:
        """Get all active attack chains"""
        return [
            chain_data for chain_data in self.chains.values()
            if chain_data.get('is_active', False)
        ]

    def detect_iot_lateral_movement(
        self,
        source_ip: str,
        dest_ip: str,
        source_zone: str,
        dest_zone: str,
        source_device_type: str = "unknown",
        dest_device_type: str = "unknown"
    ) -> Optional[dict]:
        """
        Detect IoT-to-IoT lateral movement (CRITICAL security event).

        IoT devices should NEVER communicate directly with each other.
        Any IoT-to-IoT traffic indicates compromise.

        Args:
            source_ip: Source IP address
            dest_ip: Destination IP address
            source_zone: Source device zone
            dest_zone: Destination device zone
            source_device_type: Source device type
            dest_device_type: Destination device type

        Returns:
            Detection result dict if lateral movement detected
        """
        # CRITICAL: Detect IoT-to-IoT communication
        is_iot_lateral = (
            source_zone == "iot" and dest_zone == "iot" and
            source_ip != dest_ip  # Not same device
        )

        if is_iot_lateral:
            logger.critical(
                f"IoT LATERAL MOVEMENT DETECTED: {source_ip} ({source_device_type}) "
                f"→ {dest_ip} ({dest_device_type})"
            )

            # Record as compromise with maximum severity
            chain_info = self.record_compromise(
                source_ip=source_ip,
                target_ip=dest_ip,
                attack_type="IOT_LATERAL_MOVEMENT",
                severity="critical",
                confidence=0.95  # Very high confidence - this should never happen
            )

            result = {
                'alert_type': 'IOT_LATERAL_MOVEMENT',
                'severity': 'critical',
                'confidence': 0.95,
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'source_device_type': source_device_type,
                'dest_device_type': dest_device_type,
                'recommended_action': 'IMMEDIATE_ISOLATION_BOTH_DEVICES',
                'chain_info': chain_info,
                'threat_level': 'IMMINENT_BREACH'
            }

            # Log to database
            self._log_iot_lateral_event(result)

            return result

        # Check for other suspicious cross-zone patterns
        suspicious_patterns = self._check_suspicious_zone_patterns(
            source_ip, dest_ip, source_zone, dest_zone,
            source_device_type, dest_device_type
        )

        if suspicious_patterns:
            return suspicious_patterns

        return None

    def _check_suspicious_zone_patterns(
        self,
        source_ip: str,
        dest_ip: str,
        source_zone: str,
        dest_zone: str,
        source_device_type: str,
        dest_device_type: str
    ) -> Optional[dict]:
        """Check for other suspicious cross-zone communication patterns."""

        # Pattern 1: Guest device attacking IoT
        if source_zone == "guest" and dest_zone == "iot":
            logger.warning(f"Guest device {source_ip} accessing IoT device {dest_ip}")
            return {
                'alert_type': 'GUEST_TO_IOT_ACCESS',
                'severity': 'high',
                'confidence': 0.85,
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'recommended_action': 'MONITOR_AND_RATE_LIMIT'
            }

        # Pattern 2: Quarantine breach attempt
        if source_zone == "quarantine":
            logger.critical(f"Quarantined device {source_ip} attempting to communicate with {dest_ip}")
            return {
                'alert_type': 'QUARANTINE_BREACH_ATTEMPT',
                'severity': 'critical',
                'confidence': 0.99,
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'recommended_action': 'REINFORCE_ISOLATION'
            }

        # Pattern 3: IoT device accessing Main network (unusual)
        if source_zone == "iot" and dest_zone == "main":
            logger.warning(f"IoT device {source_ip} accessing Main network device {dest_ip}")
            return {
                'alert_type': 'IOT_TO_MAIN_ACCESS',
                'severity': 'medium',
                'confidence': 0.70,
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'recommended_action': 'VERIFY_LEGITIMATE_TRAFFIC'
            }

        return None

    def detect_cascade_compromise(
        self,
        chain_id: str,
        time_window_minutes: int = 30
    ) -> Optional[dict]:
        """
        Detect rapid cascade compromise (multiple devices compromised quickly).

        Indicates automated worm/botnet propagation.

        Args:
            chain_id: Chain ID to analyze
            time_window_minutes: Time window for cascade detection

        Returns:
            Cascade detection result if detected
        """
        if chain_id not in self.chains:
            return None

        chain_data = self.chains[chain_id]
        attack_sequence = chain_data.get('attack_sequence', [])

        if len(attack_sequence) < 3:
            return None  # Need at least 3 compromises for cascade

        # Check if multiple compromises happened within time window
        current_time = datetime.now()
        time_window = timedelta(minutes=time_window_minutes)

        recent_compromises = [
            edge for edge in attack_sequence
            if current_time - datetime.fromisoformat(edge['timestamp']) < time_window
        ]

        if len(recent_compromises) >= 3:
            logger.critical(
                f"CASCADE COMPROMISE DETECTED: {len(recent_compromises)} devices "
                f"compromised in {time_window_minutes} minutes (Chain: {chain_id})"
            )

            return {
                'alert_type': 'CASCADE_COMPROMISE',
                'severity': 'critical',
                'chain_id': chain_id,
                'devices_compromised': len(recent_compromises),
                'time_window_minutes': time_window_minutes,
                'compromised_ips': [edge['target'] for edge in recent_compromises],
                'recommended_action': 'NETWORK_WIDE_LOCKDOWN'
            }

        return None

    def analyze_attack_vector(self, chain_id: str) -> dict:
        """
        Analyze attack vector and propagation method.

        Identifies:
        - Initial entry point
        - Propagation method (SSH, SMB, exploits)
        - Target selection pattern
        - Attack timeline

        Args:
            chain_id: Chain ID to analyze

        Returns:
            Attack vector analysis
        """
        if chain_id not in self.chains:
            return {}

        chain_data = self.chains[chain_id]
        attack_sequence = chain_data.get('attack_sequence', [])

        if not attack_sequence:
            return {}

        # Analyze attack types
        attack_types = [edge['attack_type'] for edge in attack_sequence]
        attack_type_counts = {}
        for attack_type in attack_types:
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1

        # Determine primary vector
        primary_vector = max(attack_type_counts, key=attack_type_counts.get) if attack_type_counts else "unknown"

        # Analyze timeline
        timestamps = [datetime.fromisoformat(edge['timestamp']) for edge in attack_sequence]
        if len(timestamps) >= 2:
            total_duration = (timestamps[-1] - timestamps[0]).total_seconds()
            avg_time_between_hops = total_duration / (len(timestamps) - 1)
        else:
            total_duration = 0
            avg_time_between_hops = 0

        # Determine propagation speed
        if avg_time_between_hops < 60:
            propagation_speed = "RAPID_AUTOMATED"  # < 1 minute = likely worm
        elif avg_time_between_hops < 300:
            propagation_speed = "MODERATE_AUTOMATED"  # < 5 minutes
        else:
            propagation_speed = "MANUAL_OR_SLOW"

        return {
            'chain_id': chain_id,
            'root_device': chain_data['root_device_ip'],
            'total_compromises': len(attack_sequence),
            'primary_vector': primary_vector,
            'attack_type_distribution': attack_type_counts,
            'propagation_speed': propagation_speed,
            'avg_time_between_hops_seconds': avg_time_between_hops,
            'total_duration_seconds': total_duration,
            'attack_timeline': [
                {
                    'timestamp': edge['timestamp'],
                    'source': edge['source'],
                    'target': edge['target'],
                    'attack_type': edge['attack_type']
                }
                for edge in attack_sequence
            ]
        }

    def _log_iot_lateral_event(self, event: dict):
        """Log IoT lateral movement event to database."""
        try:
            import uuid as uuid_module
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Log as special threat type
            event_id = f"iot-lateral-{uuid_module.uuid4().hex[:8]}"
            timestamp = datetime.now().isoformat()

            cursor.execute("""
                INSERT INTO threats (
                    id, timestamp, type, severity, source_ip, target_ip,
                    target_device, protocol, detected_by, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id,
                timestamp,
                event['alert_type'],
                event['severity'],
                event['source_ip'],
                0,  # source_port
                event['dest_ip'],
                0,  # target_port
                f"{event['source_device_type']} -> {event['dest_device_type']}",
                "tcp",
                "attack_chain_tracker",
                json.dumps({
                    'confidence': event['confidence'],
                    'recommended_action': event['recommended_action'],
                    'threat_level': event.get('threat_level')
                })
            ))

            conn.commit()
            conn.close()

            logger.info(f"Logged IoT lateral movement event: {event_id}")

        except Exception as e:
            logger.error(f"Failed to log IoT lateral movement event: {e}")

    def get_iot_compromise_statistics(self) -> dict:
        """Get statistics on IoT device compromises."""
        iot_compromises = 0
        iot_chains = 0

        for chain_data in self.chains.values():
            if not chain_data.get('is_active'):
                continue

            # Check if chain involves IoT devices
            attack_sequence = chain_data.get('attack_sequence', [])
            for edge in attack_sequence:
                if edge.get('attack_type') == 'IOT_LATERAL_MOVEMENT':
                    iot_compromises += 1
                    iot_chains += 1
                    break  # Count chain once

        return {
            'total_iot_lateral_events': iot_compromises,
            'total_iot_chains': iot_chains,
            'active_chains': len([c for c in self.chains.values() if c.get('is_active')])
        }
