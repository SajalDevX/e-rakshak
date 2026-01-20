#!/usr/bin/env python3
"""
Device Confidence Manager
=========================

Manages device identity confidence scores with:
- Time-based confidence decay
- Re-evaluation triggers
- State transitions
- Anomaly tracking

Confidence decay ensures devices are continuously re-verified,
implementing the "assume breach" mentality.

Author: Team RAKSHAK
"""

import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional
from dataclasses import dataclass

from loguru import logger


@dataclass
class ConfidenceUpdate:
    """Confidence score update."""
    old_confidence: float
    new_confidence: float
    old_state: str
    new_state: str
    reason: str
    requires_action: bool = False


class ConfidenceManager:
    """
    Manages device identity confidence with decay and re-evaluation.

    Features:
    - Time-based confidence decay (default: 1% per day)
    - Automatic re-evaluation triggers
    - State transitions based on confidence
    - Anomaly impact on confidence
    """

    # Confidence thresholds for state transitions
    CONFIRMED_THRESHOLD = 0.75      # IDENTIFIED state
    TRUSTED_THRESHOLD = 0.80        # TRUSTED state
    SUSPICIOUS_THRESHOLD = 0.40     # Below this = SUSPICIOUS
    UNKNOWN_THRESHOLD = 0.20        # Below this = UNKNOWN

    # Decay rates (per day)
    DEFAULT_DECAY_RATE = 0.01       # 1% per day
    SUSPICIOUS_DECAY_RATE = 0.05    # 5% per day for suspicious devices
    TRUSTED_DECAY_RATE = 0.005      # 0.5% per day for trusted devices

    # Re-evaluation triggers
    DRIFT_THRESHOLD = 0.30          # Drift score triggering re-eval
    ANOMALY_THRESHOLD = 5           # Number of anomalies triggering re-eval
    MAX_CONFIDENCE_AGE_DAYS = 30    # Force re-eval after 30 days

    def __init__(self, config: dict, threat_logger=None):
        """
        Initialize confidence manager.

        Args:
            config: Configuration dictionary
            threat_logger: ThreatLogger instance for database access
        """
        self.config = config
        self.threat_logger = threat_logger

        # Configuration
        confidence_config = config.get("fingerprinting", {}).get("confidence_management", {})
        self.enabled = confidence_config.get("enabled", True)
        self.decay_interval = confidence_config.get("decay_interval", 3600)  # 1 hour
        self.decay_rate = confidence_config.get("decay_rate", self.DEFAULT_DECAY_RATE)

        # Database path
        db_config = config.get("database", {})
        db_path = Path(db_config.get("path", "data/rakshak.db"))
        self.db_path = db_path

        # Background decay thread
        self._running = False
        self._decay_thread = None
        self._lock = threading.Lock()

        # Statistics
        self.stats = {
            "total_updates": 0,
            "confidence_increases": 0,
            "confidence_decreases": 0,
            "re_evaluations_triggered": 0,
            "state_transitions": 0
        }

        logger.info(f"ConfidenceManager initialized (decay_rate={self.decay_rate})")

    def start(self):
        """Start confidence decay background task."""
        if not self.enabled:
            logger.warning("ConfidenceManager is disabled in config")
            return

        if self._running:
            logger.warning("ConfidenceManager already running")
            return

        self._running = True
        self._decay_thread = threading.Thread(
            target=self._decay_loop,
            daemon=True,
            name="ConfidenceDecay"
        )
        self._decay_thread.start()
        logger.info("ConfidenceManager started")

    def stop(self):
        """Stop confidence decay background task."""
        if not self._running:
            return

        self._running = False
        if self._decay_thread:
            self._decay_thread.join(timeout=5)
        logger.info("ConfidenceManager stopped")

    def update_confidence(
        self,
        device_ip: str,
        device_mac: str,
        new_confidence: float,
        signals_collected: int = 0,
        reason: str = "manual_update"
    ) -> Optional[ConfidenceUpdate]:
        """
        Update device confidence score.

        Args:
            device_ip: Device IP address
            device_mac: Device MAC address
            new_confidence: New confidence score (0.0-1.0)
            signals_collected: Number of signals collected
            reason: Reason for update

        Returns:
            ConfidenceUpdate object
        """
        # Clamp confidence to [0.0, 1.0]
        new_confidence = max(0.0, min(1.0, new_confidence))

        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Get current confidence
            cursor.execute("""
                SELECT confidence_score, state FROM device_confidence
                WHERE device_ip = ?
            """, (device_ip,))
            result = cursor.fetchone()

            if result:
                old_confidence, old_state = result
            else:
                old_confidence = 0.0
                old_state = "DISCOVERED"

            # Determine new state based on confidence
            new_state = self._determine_state(new_confidence)

            # Check if state changed
            state_changed = old_state != new_state

            # Update database
            if self.threat_logger:
                self.threat_logger.update_device_confidence(
                    device_ip=device_ip,
                    device_mac=device_mac,
                    confidence_score=new_confidence,
                    state=new_state,
                    signals_collected=signals_collected
                )
            else:
                # Direct update if no threat_logger
                timestamp = datetime.now().isoformat()
                cursor.execute("""
                    UPDATE device_confidence
                    SET confidence_score = ?,
                        state = ?,
                        signals_collected = ?,
                        last_confidence_update = ?
                    WHERE device_ip = ?
                """, (new_confidence, new_state, signals_collected, timestamp, device_ip))

            conn.commit()
            conn.close()

            # Create update object
            update = ConfidenceUpdate(
                old_confidence=old_confidence,
                new_confidence=new_confidence,
                old_state=old_state,
                new_state=new_state,
                reason=reason,
                requires_action=state_changed
            )

            # Update statistics
            with self._lock:
                self.stats["total_updates"] += 1
                if new_confidence > old_confidence:
                    self.stats["confidence_increases"] += 1
                elif new_confidence < old_confidence:
                    self.stats["confidence_decreases"] += 1
                if state_changed:
                    self.stats["state_transitions"] += 1

            logger.info(
                f"Confidence updated for {device_ip}: {old_confidence:.2f} → {new_confidence:.2f} "
                f"({old_state} → {new_state})"
            )

            return update

        except Exception as e:
            logger.error(f"Failed to update confidence for {device_ip}: {e}")
            return None

    def apply_decay(self, device_ip: str, hours_elapsed: float = 24.0) -> Optional[float]:
        """
        Apply time-based confidence decay to a device.

        Args:
            device_ip: Device IP address
            hours_elapsed: Hours since last update

        Returns:
            New confidence score or None if failed
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Get current confidence and state
            cursor.execute("""
                SELECT confidence_score, state, device_mac, last_confidence_update
                FROM device_confidence
                WHERE device_ip = ?
            """, (device_ip,))
            result = cursor.fetchone()

            if not result:
                conn.close()
                return None

            current_confidence, state, device_mac, last_update = result

            # Determine decay rate based on state
            if state == "TRUSTED":
                decay_rate = self.TRUSTED_DECAY_RATE
            elif state in ("SUSPICIOUS", "COMPROMISED"):
                decay_rate = self.SUSPICIOUS_DECAY_RATE
            else:
                decay_rate = self.DEFAULT_DECAY_RATE

            # Calculate decay
            days_elapsed = hours_elapsed / 24.0
            decay_amount = decay_rate * days_elapsed
            new_confidence = max(0.0, current_confidence - decay_amount)

            conn.close()

            # Update confidence if changed
            if abs(new_confidence - current_confidence) > 0.001:
                self.update_confidence(
                    device_ip=device_ip,
                    device_mac=device_mac,
                    new_confidence=new_confidence,
                    reason=f"time_decay_{days_elapsed:.1f}d"
                )

            return new_confidence

        except Exception as e:
            logger.error(f"Failed to apply decay for {device_ip}: {e}")
            return None

    def check_re_evaluation_needed(self, device_ip: str) -> bool:
        """
        Check if device needs re-evaluation.

        Triggers:
        - High drift score (≥0.30)
        - Many anomalies (≥5)
        - Old confidence (>30 days)
        - Low confidence (<0.40)

        Args:
            device_ip: Device IP address

        Returns:
            True if re-evaluation needed
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Get device data
            cursor.execute("""
                SELECT
                    dc.confidence_score,
                    dc.drift_score,
                    dc.anomaly_count,
                    dc.last_confidence_update,
                    dc.re_evaluation_needed
                FROM device_confidence dc
                WHERE dc.device_ip = ?
            """, (device_ip,))
            result = cursor.fetchone()
            conn.close()

            if not result:
                return False

            confidence, drift_score, anomaly_count, last_update, re_eval_flag = result

            # Check manual flag
            if re_eval_flag:
                logger.info(f"Re-evaluation needed for {device_ip}: manual flag set")
                return True

            # Check drift score
            if drift_score and drift_score >= self.DRIFT_THRESHOLD:
                logger.info(f"Re-evaluation needed for {device_ip}: high drift ({drift_score:.2f})")
                return True

            # Check anomaly count
            if anomaly_count and anomaly_count >= self.ANOMALY_THRESHOLD:
                logger.info(f"Re-evaluation needed for {device_ip}: many anomalies ({anomaly_count})")
                return True

            # Check confidence age
            if last_update:
                last_update_dt = datetime.fromisoformat(last_update)
                age_days = (datetime.now() - last_update_dt).days
                if age_days >= self.MAX_CONFIDENCE_AGE_DAYS:
                    logger.info(f"Re-evaluation needed for {device_ip}: old confidence ({age_days} days)")
                    return True

            # Check low confidence
            if confidence < self.SUSPICIOUS_THRESHOLD:
                logger.info(f"Re-evaluation needed for {device_ip}: low confidence ({confidence:.2f})")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to check re-evaluation for {device_ip}: {e}")
            return False

    def trigger_re_evaluation(self, device_ip: str, device_mac: str):
        """
        Mark device for re-evaluation.

        Args:
            device_ip: Device IP address
            device_mac: Device MAC address
        """
        if self.threat_logger:
            self.threat_logger.update_device_confidence(
                device_ip=device_ip,
                device_mac=device_mac,
                confidence_score=0.0,  # Will be recalculated
                state="FINGERPRINTING",
                re_evaluation_needed=True
            )

        with self._lock:
            self.stats["re_evaluations_triggered"] += 1

        logger.warning(f"Triggered re-evaluation for {device_ip}")

    def _determine_state(self, confidence: float) -> str:
        """
        Determine device state based on confidence score.

        Args:
            confidence: Confidence score (0.0-1.0)

        Returns:
            Device state string
        """
        if confidence >= self.TRUSTED_THRESHOLD:
            return "TRUSTED"
        elif confidence >= self.CONFIRMED_THRESHOLD:
            return "IDENTIFIED"
        elif confidence >= self.SUSPICIOUS_THRESHOLD:
            return "FINGERPRINTING"
        elif confidence >= self.UNKNOWN_THRESHOLD:
            return "SUSPICIOUS"
        else:
            return "DISCOVERED"

    def _decay_loop(self):
        """Background loop for applying confidence decay."""
        logger.info("Confidence decay loop started")

        while self._running:
            try:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                # Get all devices with confidence tracking
                cursor.execute("""
                    SELECT
                        device_ip,
                        last_confidence_update
                    FROM device_confidence
                    WHERE confidence_score > 0
                """)
                devices = cursor.fetchall()
                conn.close()

                decayed = 0
                for device_ip, last_update in devices:
                    try:
                        # Calculate time since last update
                        if last_update:
                            last_update_dt = datetime.fromisoformat(last_update)
                            hours_elapsed = (datetime.now() - last_update_dt).total_seconds() / 3600
                        else:
                            hours_elapsed = 24.0  # Default 1 day

                        # Apply decay
                        new_conf = self.apply_decay(device_ip, hours_elapsed)
                        if new_conf is not None:
                            decayed += 1

                    except Exception as e:
                        logger.error(f"Error decaying confidence for {device_ip}: {e}")

                if decayed > 0:
                    logger.debug(f"Applied confidence decay to {decayed} devices")

                # Sleep until next decay cycle
                time.sleep(self.decay_interval)

            except Exception as e:
                logger.error(f"Error in confidence decay loop: {e}")
                time.sleep(300)  # Sleep 5 minutes on error

    def get_statistics(self) -> dict:
        """Get confidence manager statistics."""
        with self._lock:
            return self.stats.copy()
