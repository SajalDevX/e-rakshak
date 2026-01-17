#!/usr/bin/env python3
"""
Automatic Zero-Trust Zone Manager
==================================

Automatically assigns devices to security zones based on:
- Identity confidence (from multi-signal fingerprinting)
- Risk score (from behavior analysis)
- Device type (camera, laptop, etc.)
- Attack indicators

Decision Tree Logic:
- High confidence (≥0.80) + Low risk (<30) → MAIN or IOT (by device type)
- Medium confidence (≥0.60) + Medium risk (<50) → IOT (restricted)
- Low confidence (<0.60) OR High risk (≥50) → GUEST
- Critical risk (≥80) OR Active attack → QUARANTINE

Author: Team RAKSHAK
"""

import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from loguru import logger


class SecurityZone(Enum):
    """Security zones for zero-trust enforcement."""
    MAIN = "main"           # Trusted devices (laptops, phones)
    IOT = "iot"             # IoT devices (cameras, smart devices)
    GUEST = "guest"         # Untrusted/unknown devices
    MGMT = "mgmt"           # Management devices
    QUARANTINE = "quarantine"  # Compromised/high-risk devices


class DeviceState(Enum):
    """Device identity states."""
    DISCOVERED = "DISCOVERED"         # Just discovered
    FINGERPRINTING = "FINGERPRINTING" # Collecting signals
    IDENTIFIED = "IDENTIFIED"         # Confidence >= 0.75
    TRUSTED = "TRUSTED"              # Confidence >= 0.80, low risk
    SUSPICIOUS = "SUSPICIOUS"        # Anomalies detected
    COMPROMISED = "COMPROMISED"      # Active attack


@dataclass
class ZoneAssignment:
    """Zone assignment decision."""
    zone: str
    reason: str
    confidence: float
    risk_score: int
    device_type: str
    auto_assigned: bool = True


class AutomaticZoneManager:
    """
    Manages automatic zone assignment based on identity confidence and risk.

    Features:
    - Decision tree logic for zone assignment
    - Continuous monitoring and re-evaluation
    - Zone change auditing
    - Integration with trust_manager
    """

    # Decision thresholds
    HIGH_CONFIDENCE_THRESHOLD = 0.80
    MEDIUM_CONFIDENCE_THRESHOLD = 0.60
    LOW_RISK_THRESHOLD = 30
    MEDIUM_RISK_THRESHOLD = 50
    HIGH_RISK_THRESHOLD = 80

    # Trusted device types (allowed in MAIN zone)
    TRUSTED_DEVICE_TYPES = {
        "laptop", "desktop", "workstation", "phone", "tablet",
        "mobile", "smartphone", "pc", "macbook", "iphone", "android"
    }

    # IoT device types (restricted to IOT zone)
    IOT_DEVICE_TYPES = {
        "camera", "smart_plug", "smart_bulb", "smart_switch",
        "smart_speaker", "doorbell", "thermostat", "sensor",
        "nvr", "dvr", "iot", "alexa", "chromecast", "fire_tv",
        "smart_tv", "router", "hub", "vacuum", "light_strip"
    }

    def __init__(self, config: dict, trust_manager=None, threat_logger=None):
        """
        Initialize automatic zone manager.

        Args:
            config: Configuration dictionary
            trust_manager: TrustManager instance for zone changes
            threat_logger: ThreatLogger instance for database access
        """
        self.config = config
        self.trust_manager = trust_manager
        self.threat_logger = threat_logger

        # Configuration
        zone_config = config.get("zero_trust", {}).get("automatic_assignment", {})
        self.enabled = zone_config.get("enabled", True)
        self.auto_quarantine = zone_config.get("auto_quarantine", True)
        self.re_evaluation_interval = zone_config.get("re_evaluation_interval", 300)  # 5 minutes

        # Database path
        db_config = config.get("database", {})
        db_path = Path(db_config.get("path", "data/rakshak.db"))
        self.db_path = db_path

        # Monitoring thread
        self._running = False
        self._monitor_thread = None
        self._lock = threading.Lock()

        # Statistics
        self.stats = {
            "total_assignments": 0,
            "auto_assignments": 0,
            "manual_overrides": 0,
            "quarantines": 0,
            "zone_changes": {
                "main": 0,
                "iot": 0,
                "guest": 0,
                "quarantine": 0
            }
        }

        logger.info(f"AutomaticZoneManager initialized (enabled={self.enabled})")

    def start(self):
        """Start automatic zone monitoring."""
        if not self.enabled:
            logger.warning("AutomaticZoneManager is disabled in config")
            return

        if self._running:
            logger.warning("AutomaticZoneManager already running")
            return

        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="ZoneMonitor"
        )
        self._monitor_thread.start()
        logger.info("AutomaticZoneManager started")

    def stop(self):
        """Stop automatic zone monitoring."""
        if not self._running:
            return

        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("AutomaticZoneManager stopped")

    def assign_zone(
        self,
        device_ip: str,
        device_mac: str,
        confidence: float,
        risk_score: int,
        device_type: str = "unknown",
        current_zone: str = "guest",
        force: bool = False
    ) -> Optional[ZoneAssignment]:
        """
        Determine appropriate zone for device based on decision tree.

        Args:
            device_ip: Device IP address
            device_mac: Device MAC address
            confidence: Identity confidence (0.0-1.0)
            risk_score: Risk score (0-100)
            device_type: Device type
            current_zone: Current zone assignment
            force: Force zone change even if already in correct zone

        Returns:
            ZoneAssignment object or None if no change needed
        """
        # Decision tree logic
        new_zone, reason = self._evaluate_zone(
            confidence=confidence,
            risk_score=risk_score,
            device_type=device_type
        )

        # Check if zone change is needed
        if new_zone == current_zone and not force:
            logger.debug(f"Device {device_ip} already in correct zone: {new_zone}")
            return None

        # Create assignment
        assignment = ZoneAssignment(
            zone=new_zone,
            reason=reason,
            confidence=confidence,
            risk_score=risk_score,
            device_type=device_type,
            auto_assigned=True
        )

        # Apply zone change via trust_manager
        if self.trust_manager:
            try:
                # Map zone names to trust_manager format
                zone_map = {
                    "main": "main",
                    "iot": "iot",
                    "guest": "guest",
                    "mgmt": "mgmt",
                    "quarantine": "quarantine"
                }

                trust_zone = zone_map.get(new_zone, "guest")
                self.trust_manager.assign_zone(device_ip, trust_zone)

                # Log zone change
                self._log_zone_change(
                    device_mac=device_mac,
                    old_zone=current_zone,
                    new_zone=new_zone,
                    reason=reason,
                    confidence=confidence,
                    risk_score=risk_score
                )

                logger.info(
                    f"Auto-assigned {device_ip} to {new_zone.upper()} zone "
                    f"(confidence={confidence:.2f}, risk={risk_score}, type={device_type})"
                )

            except Exception as e:
                logger.error(f"Failed to assign zone for {device_ip}: {e}")
                return None

        # Update statistics
        with self._lock:
            self.stats["total_assignments"] += 1
            self.stats["auto_assignments"] += 1
            self.stats["zone_changes"][new_zone] = \
                self.stats["zone_changes"].get(new_zone, 0) + 1

            if new_zone == "quarantine":
                self.stats["quarantines"] += 1

        return assignment

    def _evaluate_zone(
        self,
        confidence: float,
        risk_score: int,
        device_type: str
    ) -> Tuple[str, str]:
        """
        Evaluate appropriate zone using decision tree.

        Returns:
            Tuple of (zone, reason)
        """
        device_type_lower = device_type.lower()

        # CRITICAL: Quarantine if active attack or critical risk
        if risk_score >= self.HIGH_RISK_THRESHOLD:
            return ("quarantine", f"Critical risk score: {risk_score}")

        # HIGH CONFIDENCE + LOW RISK
        if confidence >= self.HIGH_CONFIDENCE_THRESHOLD and risk_score < self.LOW_RISK_THRESHOLD:
            # Check device type
            if any(dt in device_type_lower for dt in self.TRUSTED_DEVICE_TYPES):
                return ("main", f"High confidence ({confidence:.2f}), trusted device type")
            elif any(dt in device_type_lower for dt in self.IOT_DEVICE_TYPES):
                return ("iot", f"High confidence ({confidence:.2f}), IoT device type")
            else:
                # Unknown device type with high confidence → conservative IOT zone
                return ("iot", f"High confidence ({confidence:.2f}), unknown device type")

        # MEDIUM CONFIDENCE + MEDIUM RISK
        if confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD and risk_score < self.MEDIUM_RISK_THRESHOLD:
            # Restrict to IOT zone with limited privileges
            return ("iot", f"Medium confidence ({confidence:.2f}), restricted access")

        # LOW CONFIDENCE OR MEDIUM-HIGH RISK
        if confidence < self.MEDIUM_CONFIDENCE_THRESHOLD or risk_score >= self.MEDIUM_RISK_THRESHOLD:
            # Unknown devices or moderate risk → GUEST zone
            return ("guest", f"Low confidence ({confidence:.2f}) or elevated risk ({risk_score})")

        # Default: GUEST (fail-safe)
        return ("guest", f"Default assignment (confidence={confidence:.2f}, risk={risk_score})")

    def evaluate_all_devices(self):
        """
        Re-evaluate all devices and update zone assignments.

        Called periodically by monitoring loop or manually triggered.
        """
        if not self.enabled:
            return

        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Get all active devices with confidence and risk data
            cursor.execute("""
                SELECT
                    d.ip,
                    d.mac,
                    d.zone,
                    d.device_type,
                    d.risk_score,
                    COALESCE(dc.confidence_score, 0.0) as confidence,
                    COALESCE(dc.state, 'DISCOVERED') as state,
                    COALESCE(dc.drift_score, 0.0) as drift_score,
                    d.isolation_level
                FROM devices d
                LEFT JOIN device_confidence dc ON d.ip = dc.device_ip
                WHERE d.status = 'active'
            """)

            devices = cursor.fetchall()
            conn.close()

            evaluated = 0
            changed = 0

            for device in devices:
                ip, mac, zone, device_type, risk_score, confidence, state, drift_score, isolation = device

                # Skip isolated devices (managed separately)
                if isolation and isolation != "none":
                    continue

                # Adjust risk score based on drift
                adjusted_risk = risk_score + int(drift_score * 50)  # Drift can add up to +50 risk

                # Evaluate zone assignment
                assignment = self.assign_zone(
                    device_ip=ip,
                    device_mac=mac,
                    confidence=confidence,
                    risk_score=adjusted_risk,
                    device_type=device_type or "unknown",
                    current_zone=zone or "guest",
                    force=False
                )

                evaluated += 1
                if assignment:
                    changed += 1

            logger.info(f"Re-evaluated {evaluated} devices, {changed} zone changes made")

        except Exception as e:
            logger.error(f"Failed to evaluate devices: {e}")

    def _monitoring_loop(self):
        """Background monitoring loop for continuous re-evaluation."""
        logger.info("Zone monitoring loop started")

        while self._running:
            try:
                # Re-evaluate all devices
                self.evaluate_all_devices()

                # Sleep until next evaluation
                time.sleep(self.re_evaluation_interval)

            except Exception as e:
                logger.error(f"Error in zone monitoring loop: {e}")
                time.sleep(60)  # Sleep 1 minute on error

    def _log_zone_change(
        self,
        device_mac: str,
        old_zone: str,
        new_zone: str,
        reason: str,
        confidence: float,
        risk_score: int
    ):
        """Log zone change to database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            timestamp = datetime.now().isoformat()

            cursor.execute("""
                INSERT INTO zone_history (
                    device_mac, old_zone, new_zone, changed_at, changed_by, reason
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                device_mac,
                old_zone,
                new_zone,
                timestamp,
                "automatic_zone_manager",
                f"{reason} (confidence={confidence:.2f}, risk={risk_score})"
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Failed to log zone change: {e}")

    def force_quarantine(
        self,
        device_ip: str,
        device_mac: str,
        reason: str,
        duration: Optional[int] = None
    ):
        """
        Force a device into quarantine zone.

        Args:
            device_ip: Device IP address
            device_mac: Device MAC address
            reason: Reason for quarantine
            duration: Optional quarantine duration in seconds
        """
        if not self.auto_quarantine:
            logger.warning(f"Auto-quarantine disabled, cannot quarantine {device_ip}")
            return

        try:
            # Get current zone
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT zone FROM devices WHERE ip = ?", (device_ip,))
            result = cursor.fetchone()
            current_zone = result[0] if result else "guest"
            conn.close()

            # Assign to quarantine
            if self.trust_manager:
                self.trust_manager.assign_zone(device_ip, "quarantine")

            # Log change
            self._log_zone_change(
                device_mac=device_mac,
                old_zone=current_zone,
                new_zone="quarantine",
                reason=f"Force quarantine: {reason}",
                confidence=0.0,
                risk_score=100
            )

            logger.warning(f"Force quarantined {device_ip}: {reason}")

            # Update statistics
            with self._lock:
                self.stats["quarantines"] += 1
                self.stats["zone_changes"]["quarantine"] += 1

        except Exception as e:
            logger.error(f"Failed to force quarantine {device_ip}: {e}")

    def get_statistics(self) -> dict:
        """Get zone assignment statistics."""
        with self._lock:
            return self.stats.copy()
