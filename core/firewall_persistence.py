#!/usr/bin/env python3
"""
RAKSHAK Firewall Persistence Module
====================================

Persist device isolation state across reboots.

Features:
- Save isolation state to database
- Restore isolations on startup
- Automatic expiration of time-limited isolations
- Audit trail of isolation events

Author: Team RAKSHAK
"""

import sqlite3
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from pathlib import Path

from loguru import logger


class FirewallPersistence:
    """
    Persist firewall isolation state across reboots.

    Stores device isolation state in database and restores
    on system startup to ensure continuous protection.
    """

    def __init__(self, db_path: str):
        """
        Initialize firewall persistence manager.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        logger.info("FirewallPersistence initialized")

    def save_isolation_state(self, ip: str, mac_address: Optional[str],
                             level: str, reason: str,
                             expires_at: Optional[datetime] = None) -> bool:
        """
        Save isolation to database for reboot survival.

        Args:
            ip: IP address to isolate
            mac_address: MAC address (optional)
            level: Isolation level (full, internet, rate_limited, honeypot)
            reason: Reason for isolation
            expires_at: Optional expiration datetime

        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Insert or replace isolation state
            cursor.execute("""
                INSERT OR REPLACE INTO persistent_isolations
                (ip_address, mac_address, isolation_level, reason,
                 isolated_at, expires_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ip,
                mac_address,
                level,
                reason,
                datetime.now().isoformat(),
                expires_at.isoformat() if expires_at else None,
                1  # is_active
            ))

            conn.commit()
            conn.close()

            logger.info(f"Saved isolation state for {ip} (level: {level})")
            return True

        except Exception as e:
            logger.error(f"Failed to save isolation state: {e}")
            return False

    def restore_isolations_on_startup(self, gateway) -> int:
        """
        Restore all active isolations from database.

        Args:
            gateway: RakshakGateway instance

        Returns:
            Number of isolations restored
        """
        logger.info("Restoring persistent isolations from database")

        # First, expire old isolations
        self.expire_old_isolations()

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get all active isolations
            cursor.execute("""
                SELECT ip_address, mac_address, isolation_level, reason, expires_at
                FROM persistent_isolations
                WHERE is_active = 1
            """)

            isolations = cursor.fetchall()
            conn.close()

            count = 0
            for ip, mac, level, reason, expires_at in isolations:
                logger.info(f"Restoring isolation for {ip} (level: {level})")

                # Convert level string to enum
                from core.gateway import IsolationLevel

                level_map = {
                    "full": IsolationLevel.FULL,
                    "internet": IsolationLevel.INTERNET_ONLY,
                    "rate_limited": IsolationLevel.RATE_LIMITED,
                    "honeypot": IsolationLevel.HONEYPOT
                }

                isolation_level = level_map.get(level, IsolationLevel.FULL)

                # Calculate remaining duration if expiration is set
                duration_minutes = None
                if expires_at:
                    expires_dt = datetime.fromisoformat(expires_at)
                    remaining = expires_dt - datetime.now()
                    if remaining.total_seconds() > 0:
                        duration_minutes = int(remaining.total_seconds() / 60)

                # Restore isolation using enhanced method
                success = gateway.isolate_device_enhanced(
                    ip_address=ip,
                    level=isolation_level,
                    reason=f"[RESTORED] {reason}",
                    duration_minutes=duration_minutes,
                    kill_existing_connections=False,  # Don't kill on restore
                    persist_across_reboot=False,  # Already in DB
                    mac_address=mac
                )

                if success:
                    count += 1

            logger.info(f"Restored {count} persistent isolations")
            return count

        except Exception as e:
            logger.error(f"Failed to restore isolations: {e}")
            return 0

    def expire_old_isolations(self) -> int:
        """
        Mark expired isolations as inactive.

        Returns:
            Number of isolations expired
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Expire isolations where expires_at < now
            cursor.execute("""
                UPDATE persistent_isolations
                SET is_active = 0
                WHERE is_active = 1
                  AND expires_at IS NOT NULL
                  AND expires_at < ?
            """, (datetime.now().isoformat(),))

            expired_count = cursor.rowcount
            conn.commit()
            conn.close()

            if expired_count > 0:
                logger.info(f"Expired {expired_count} old isolations")

            return expired_count

        except Exception as e:
            logger.error(f"Failed to expire old isolations: {e}")
            return 0

    def remove_isolation_state(self, ip: str) -> bool:
        """
        Remove isolation state for an IP address.

        Args:
            ip: IP address

        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE persistent_isolations
                SET is_active = 0
                WHERE ip_address = ?
            """, (ip,))

            conn.commit()
            conn.close()

            logger.info(f"Removed isolation state for {ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to remove isolation state: {e}")
            return False

    def get_active_isolations(self) -> List[Dict[str, str]]:
        """
        Get all currently active isolations.

        Returns:
            List of isolation dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT ip_address, mac_address, isolation_level, reason,
                       isolated_at, expires_at
                FROM persistent_isolations
                WHERE is_active = 1
                ORDER BY isolated_at DESC
            """)

            isolations = []
            for row in cursor.fetchall():
                isolations.append({
                    "ip_address": row[0],
                    "mac_address": row[1],
                    "isolation_level": row[2],
                    "reason": row[3],
                    "isolated_at": row[4],
                    "expires_at": row[5]
                })

            conn.close()
            return isolations

        except Exception as e:
            logger.error(f"Failed to get active isolations: {e}")
            return []

    def cleanup_old_records(self, days: int = 30) -> int:
        """
        Cleanup inactive isolation records older than specified days.

        Args:
            days: Number of days to keep records

        Returns:
            Number of records deleted
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            cursor.execute("""
                DELETE FROM persistent_isolations
                WHERE is_active = 0
                  AND isolated_at < ?
            """, (cutoff_date,))

            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old isolation records")

            return deleted_count

        except Exception as e:
            logger.error(f"Failed to cleanup old records: {e}")
            return 0
