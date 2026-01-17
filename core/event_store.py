#!/usr/bin/env python3
"""
RAKSHAK Event Store
===================

Storage backend for AttackEvents with Redis primary and in-memory fallback.

Supports:
- Redis storage (production)
- In-memory storage (development/fallback)
- JSON export for offline training
- Batch operations for efficiency

Author: Team RAKSHAK
"""

import json
import os
import threading
from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable

from loguru import logger

from .event_schema import AttackEvent

# Optional Redis import
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.debug("Redis not installed - will use memory store")


class EventStore(ABC):
    """Abstract base class for event storage."""

    @abstractmethod
    def store(self, event: AttackEvent) -> bool:
        """Store a single event."""
        pass

    @abstractmethod
    def store_batch(self, events: List[AttackEvent]) -> int:
        """Store multiple events. Returns count of stored events."""
        pass

    @abstractmethod
    def get_events(self, since: Optional[datetime] = None,
                   limit: int = 1000) -> List[AttackEvent]:
        """Get events since a timestamp."""
        pass

    @abstractmethod
    def get_all_events(self) -> List[AttackEvent]:
        """Get all stored events."""
        pass

    @abstractmethod
    def get_event_count(self) -> int:
        """Get total number of stored events."""
        pass

    @abstractmethod
    def export_json(self, path: str) -> int:
        """Export events to JSON file. Returns count exported."""
        pass

    @abstractmethod
    def clear(self) -> bool:
        """Clear all stored events."""
        pass


class MemoryEventStore(EventStore):
    """
    Thread-safe in-memory event store using deque.

    Features:
    - Fixed max size (oldest events evicted)
    - Thread-safe with RLock
    - Periodic auto-export to JSON
    """

    def __init__(self, max_size: int = 10000,
                 auto_export_path: Optional[str] = None,
                 auto_export_interval: int = 3600):
        """
        Initialize memory store.

        Args:
            max_size: Maximum events to store (FIFO eviction)
            auto_export_path: Path for auto-export (None to disable)
            auto_export_interval: Seconds between auto-exports
        """
        self.max_size = max_size
        self.events: deque = deque(maxlen=max_size)
        self.lock = threading.RLock()

        # Auto-export settings
        self.auto_export_path = auto_export_path
        self.auto_export_interval = auto_export_interval
        self._export_timer: Optional[threading.Timer] = None

        if auto_export_path:
            self._start_auto_export()

        logger.info(f"MemoryEventStore initialized (max_size={max_size})")

    def store(self, event: AttackEvent) -> bool:
        """Store a single event."""
        try:
            with self.lock:
                self.events.append(event)
            return True
        except Exception as e:
            logger.error(f"Failed to store event: {e}")
            return False

    def store_batch(self, events: List[AttackEvent]) -> int:
        """Store multiple events."""
        stored = 0
        with self.lock:
            for event in events:
                try:
                    self.events.append(event)
                    stored += 1
                except Exception as e:
                    logger.error(f"Failed to store event in batch: {e}")
        return stored

    def get_events(self, since: Optional[datetime] = None,
                   limit: int = 1000) -> List[AttackEvent]:
        """Get events since a timestamp."""
        with self.lock:
            if since is None:
                # Return most recent events
                return list(self.events)[-limit:]

            # Filter by timestamp
            filtered = [
                e for e in self.events
                if e.timestamp >= since
            ]
            return filtered[-limit:]

    def get_all_events(self) -> List[AttackEvent]:
        """Get all stored events."""
        with self.lock:
            return list(self.events)

    def get_event_count(self) -> int:
        """Get total number of stored events."""
        with self.lock:
            return len(self.events)

    def export_json(self, path: str) -> int:
        """Export events to JSON file."""
        try:
            with self.lock:
                events_list = [e.to_dict() for e in self.events]

            # Ensure directory exists
            Path(path).parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                json.dump({
                    "export_timestamp": datetime.now().isoformat(),
                    "event_count": len(events_list),
                    "events": events_list
                }, f, indent=2)

            logger.info(f"Exported {len(events_list)} events to {path}")
            return len(events_list)

        except Exception as e:
            logger.error(f"Failed to export events: {e}")
            return 0

    def clear(self) -> bool:
        """Clear all stored events."""
        try:
            with self.lock:
                self.events.clear()
            logger.info("MemoryEventStore cleared")
            return True
        except Exception as e:
            logger.error(f"Failed to clear events: {e}")
            return False

    def _start_auto_export(self):
        """Start periodic auto-export timer."""
        def export_task():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self.auto_export_path, f"events_{timestamp}.json")
            self.export_json(path)
            # Reschedule
            self._export_timer = threading.Timer(
                self.auto_export_interval, export_task
            )
            self._export_timer.daemon = True
            self._export_timer.start()

        self._export_timer = threading.Timer(
            self.auto_export_interval, export_task
        )
        self._export_timer.daemon = True
        self._export_timer.start()
        logger.info(f"Auto-export started: every {self.auto_export_interval}s to {self.auto_export_path}")

    def stop(self):
        """Stop auto-export timer."""
        if self._export_timer:
            self._export_timer.cancel()
            self._export_timer = None


class RedisEventStore(EventStore):
    """
    Redis-backed event store.

    Features:
    - LPUSH/LRANGE for efficient list operations
    - JSON serialization
    - Automatic fallback to MemoryEventStore if Redis unavailable
    - TTL support for automatic expiration
    """

    def __init__(self, redis_url: str = "redis://localhost:6379",
                 key: str = "rakshak:attack_events",
                 max_size: int = 100000,
                 ttl_days: int = 30,
                 fallback_to_memory: bool = True):
        """
        Initialize Redis store.

        Args:
            redis_url: Redis connection URL
            key: Redis key for the event list
            max_size: Maximum events to store
            ttl_days: Time-to-live for events in days
            fallback_to_memory: Use MemoryEventStore if Redis unavailable
        """
        self.redis_url = redis_url
        self.key = key
        self.max_size = max_size
        self.ttl_seconds = ttl_days * 24 * 3600

        self.client: Optional[redis.Redis] = None
        self.fallback_store: Optional[MemoryEventStore] = None
        self.using_fallback = False

        if not REDIS_AVAILABLE:
            logger.warning("Redis package not installed")
            if fallback_to_memory:
                self._setup_fallback()
            return

        try:
            self.client = redis.from_url(redis_url)
            self.client.ping()  # Test connection
            logger.info(f"RedisEventStore connected to {redis_url}")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            if fallback_to_memory:
                self._setup_fallback()
            else:
                raise

    def _setup_fallback(self):
        """Setup fallback memory store."""
        logger.info("Using MemoryEventStore as fallback")
        self.fallback_store = MemoryEventStore(max_size=self.max_size)
        self.using_fallback = True

    def store(self, event: AttackEvent) -> bool:
        """Store a single event."""
        if self.using_fallback:
            return self.fallback_store.store(event)

        try:
            # Serialize and push to Redis list
            event_json = event.to_json()
            self.client.lpush(self.key, event_json)

            # Trim to max size
            self.client.ltrim(self.key, 0, self.max_size - 1)

            return True

        except Exception as e:
            logger.error(f"Redis store failed: {e}")
            return False

    def store_batch(self, events: List[AttackEvent]) -> int:
        """Store multiple events using pipeline."""
        if self.using_fallback:
            return self.fallback_store.store_batch(events)

        try:
            pipe = self.client.pipeline()

            for event in events:
                pipe.lpush(self.key, event.to_json())

            # Trim after batch
            pipe.ltrim(self.key, 0, self.max_size - 1)

            pipe.execute()
            return len(events)

        except Exception as e:
            logger.error(f"Redis batch store failed: {e}")
            return 0

    def get_events(self, since: Optional[datetime] = None,
                   limit: int = 1000) -> List[AttackEvent]:
        """Get events since a timestamp."""
        if self.using_fallback:
            return self.fallback_store.get_events(since, limit)

        try:
            # Get raw JSON strings
            raw_events = self.client.lrange(self.key, 0, limit - 1)

            events = []
            for raw in raw_events:
                try:
                    event = AttackEvent.from_json(raw.decode('utf-8'))

                    # Filter by timestamp if specified
                    if since is None or event.timestamp >= since:
                        events.append(event)
                except Exception as e:
                    logger.warning(f"Failed to parse event: {e}")

            # Reverse to get chronological order (LPUSH adds to front)
            events.reverse()
            return events

        except Exception as e:
            logger.error(f"Redis get_events failed: {e}")
            return []

    def get_all_events(self) -> List[AttackEvent]:
        """Get all stored events."""
        if self.using_fallback:
            return self.fallback_store.get_all_events()

        return self.get_events(limit=self.max_size)

    def get_event_count(self) -> int:
        """Get total number of stored events."""
        if self.using_fallback:
            return self.fallback_store.get_event_count()

        try:
            return self.client.llen(self.key)
        except Exception as e:
            logger.error(f"Redis llen failed: {e}")
            return 0

    def export_json(self, path: str) -> int:
        """Export events to JSON file."""
        if self.using_fallback:
            return self.fallback_store.export_json(path)

        try:
            events = self.get_all_events()
            events_list = [e.to_dict() for e in events]

            # Ensure directory exists
            Path(path).parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                json.dump({
                    "export_timestamp": datetime.now().isoformat(),
                    "source": "redis",
                    "redis_key": self.key,
                    "event_count": len(events_list),
                    "events": events_list
                }, f, indent=2)

            logger.info(f"Exported {len(events_list)} events to {path}")
            return len(events_list)

        except Exception as e:
            logger.error(f"Failed to export events: {e}")
            return 0

    def clear(self) -> bool:
        """Clear all stored events."""
        if self.using_fallback:
            return self.fallback_store.clear()

        try:
            self.client.delete(self.key)
            logger.info(f"Redis key {self.key} cleared")
            return True
        except Exception as e:
            logger.error(f"Redis clear failed: {e}")
            return False


# =============================================================================
# Factory Function
# =============================================================================

def get_event_store(config: Dict[str, Any]) -> EventStore:
    """
    Factory function to create appropriate EventStore.

    Args:
        config: Configuration dictionary with event_store settings

    Returns:
        EventStore instance (Redis or Memory)
    """
    event_config = config.get("kaal", {}).get("event_store", {})

    backend = event_config.get("backend", "memory")
    max_size = event_config.get("memory_max_size", 10000)
    auto_export_path = event_config.get("export_path", "data/events/")
    auto_export_interval = event_config.get("auto_export_interval", 3600)

    if backend == "redis":
        redis_url = event_config.get("redis_url", "redis://localhost:6379")
        redis_key = event_config.get("redis_key", "rakshak:attack_events")

        return RedisEventStore(
            redis_url=redis_url,
            key=redis_key,
            max_size=max_size,
            fallback_to_memory=True
        )

    else:
        # Default to memory store
        return MemoryEventStore(
            max_size=max_size,
            auto_export_path=auto_export_path,
            auto_export_interval=auto_export_interval
        )


# =============================================================================
# Event Loading Utilities
# =============================================================================

def load_events_from_json(path: str) -> List[AttackEvent]:
    """
    Load events from a JSON file.

    Args:
        path: Path to JSON file

    Returns:
        List of AttackEvent objects
    """
    try:
        with open(path, 'r') as f:
            data = json.load(f)

        events = []
        events_data = data.get("events", data)  # Handle both formats

        if isinstance(events_data, list):
            for event_dict in events_data:
                try:
                    events.append(AttackEvent.from_dict(event_dict))
                except Exception as e:
                    logger.warning(f"Failed to parse event: {e}")

        logger.info(f"Loaded {len(events)} events from {path}")
        return events

    except Exception as e:
        logger.error(f"Failed to load events from {path}: {e}")
        return []


def load_events_from_directory(directory: str, pattern: str = "events_*.json") -> List[AttackEvent]:
    """
    Load events from all JSON files in a directory.

    Args:
        directory: Directory path
        pattern: Glob pattern for JSON files

    Returns:
        List of AttackEvent objects (sorted by timestamp)
    """
    import glob

    all_events = []
    file_pattern = os.path.join(directory, pattern)

    for filepath in glob.glob(file_pattern):
        events = load_events_from_json(filepath)
        all_events.extend(events)

    # Sort by timestamp
    all_events.sort(key=lambda e: e.timestamp)

    logger.info(f"Loaded {len(all_events)} events from {directory}")
    return all_events
