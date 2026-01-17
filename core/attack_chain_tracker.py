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
