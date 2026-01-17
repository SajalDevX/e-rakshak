#!/usr/bin/env python3
"""
RAKSHAK Event Bus
=================

Event publishing abstraction for KAAL decisions.
Supports local (Redis/Memory) and Kafka backends.

Design:
- EventPublisher: Abstract interface
- LocalEventPublisher: Writes to EventStore
- KafkaEventPublisher: Kafka-compatible (abstracted)
- AsyncEventPublisher: Non-blocking wrapper

Author: Team RAKSHAK
"""

import queue
import threading
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Callable

from loguru import logger

from .event_schema import AttackEvent
from .event_store import EventStore, get_event_store


class EventPublisher(ABC):
    """Abstract base class for event publishing."""

    @abstractmethod
    def publish(self, event: AttackEvent) -> bool:
        """
        Publish a single event.

        Args:
            event: AttackEvent to publish

        Returns:
            True if published successfully
        """
        pass

    @abstractmethod
    def publish_batch(self, events: List[AttackEvent]) -> int:
        """
        Publish multiple events.

        Args:
            events: List of AttackEvents to publish

        Returns:
            Number of events successfully published
        """
        pass

    @abstractmethod
    def flush(self) -> bool:
        """
        Flush any pending events.

        Returns:
            True if flush successful
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the publisher and release resources."""
        pass


class LocalEventPublisher(EventPublisher):
    """
    Publisher that writes to local EventStore (Redis/Memory).

    This is the primary publisher for RAKSHAK deployments.
    """

    def __init__(self, event_store: EventStore):
        """
        Initialize with an EventStore backend.

        Args:
            event_store: EventStore instance (Redis or Memory)
        """
        self.store = event_store
        self._publish_count = 0
        logger.info("LocalEventPublisher initialized")

    def publish(self, event: AttackEvent) -> bool:
        """Publish event to local store."""
        success = self.store.store(event)
        if success:
            self._publish_count += 1
        return success

    def publish_batch(self, events: List[AttackEvent]) -> int:
        """Publish batch to local store."""
        count = self.store.store_batch(events)
        self._publish_count += count
        return count

    def flush(self) -> bool:
        """No-op for local store (writes are immediate)."""
        return True

    def close(self) -> None:
        """No-op for local store."""
        pass

    @property
    def publish_count(self) -> int:
        """Total events published."""
        return self._publish_count


class KafkaEventPublisher(EventPublisher):
    """
    Kafka-compatible event publisher (abstracted).

    NOTE: This is a stub implementation for hackathon demo.
    In production, this would integrate with actual Kafka cluster.
    Currently falls back to LocalEventPublisher behavior.
    """

    def __init__(self, bootstrap_servers: str = "localhost:9092",
                 topic: str = "rakshak-attack-events",
                 fallback_store: Optional[EventStore] = None):
        """
        Initialize Kafka publisher.

        Args:
            bootstrap_servers: Kafka bootstrap servers
            topic: Kafka topic name
            fallback_store: Fallback EventStore if Kafka unavailable
        """
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.producer = None
        self._publish_count = 0

        # For hackathon: always use fallback (no real Kafka)
        self.using_fallback = True
        self.fallback_publisher = None

        if fallback_store:
            self.fallback_publisher = LocalEventPublisher(fallback_store)
            logger.info(f"KafkaEventPublisher using fallback (topic={topic})")
        else:
            logger.warning("KafkaEventPublisher: No fallback store provided")

    def publish(self, event: AttackEvent) -> bool:
        """Publish event to Kafka (or fallback)."""
        if self.using_fallback and self.fallback_publisher:
            return self.fallback_publisher.publish(event)

        # Real Kafka implementation would go here
        # self.producer.send(self.topic, event.to_json().encode())
        return False

    def publish_batch(self, events: List[AttackEvent]) -> int:
        """Publish batch to Kafka (or fallback)."""
        if self.using_fallback and self.fallback_publisher:
            return self.fallback_publisher.publish_batch(events)

        # Real Kafka batch send would go here
        return 0

    def flush(self) -> bool:
        """Flush Kafka producer."""
        if self.using_fallback and self.fallback_publisher:
            return self.fallback_publisher.flush()

        # self.producer.flush()
        return True

    def close(self) -> None:
        """Close Kafka producer."""
        if self.fallback_publisher:
            self.fallback_publisher.close()

        # self.producer.close()


class AsyncEventPublisher(EventPublisher):
    """
    Non-blocking event publisher wrapper.

    Wraps any EventPublisher with async queue-based publishing.
    Events are published in a background thread.
    """

    def __init__(self, inner_publisher: EventPublisher,
                 queue_size: int = 1000):
        """
        Initialize async wrapper.

        Args:
            inner_publisher: The publisher to wrap
            queue_size: Maximum queue size before blocking
        """
        self.inner = inner_publisher
        self.queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._running = True
        self._publish_count = 0
        self._dropped_count = 0

        # Start background worker
        self._worker = threading.Thread(target=self._publish_worker, daemon=True)
        self._worker.start()

        logger.info(f"AsyncEventPublisher initialized (queue_size={queue_size})")

    def _publish_worker(self):
        """Background thread that processes the queue."""
        batch = []
        batch_size = 10
        batch_timeout = 0.1  # seconds

        while self._running or not self.queue.empty():
            try:
                # Get events from queue
                event = self.queue.get(timeout=batch_timeout)
                batch.append(event)

                # Batch up events for efficiency
                while len(batch) < batch_size:
                    try:
                        event = self.queue.get_nowait()
                        batch.append(event)
                    except queue.Empty:
                        break

                # Publish batch
                if batch:
                    count = self.inner.publish_batch(batch)
                    self._publish_count += count
                    batch.clear()

            except queue.Empty:
                # Timeout - publish any pending batch
                if batch:
                    count = self.inner.publish_batch(batch)
                    self._publish_count += count
                    batch.clear()

            except Exception as e:
                logger.error(f"Async publisher worker error: {e}")

        # Flush remaining
        if batch:
            self.inner.publish_batch(batch)

    def publish(self, event: AttackEvent) -> bool:
        """
        Queue event for async publishing.

        Non-blocking unless queue is full.
        """
        try:
            self.queue.put_nowait(event)
            return True
        except queue.Full:
            self._dropped_count += 1
            logger.warning("Event queue full - dropping event")
            return False

    def publish_batch(self, events: List[AttackEvent]) -> int:
        """Queue multiple events."""
        queued = 0
        for event in events:
            if self.publish(event):
                queued += 1
        return queued

    def flush(self) -> bool:
        """Wait for queue to drain."""
        self.queue.join()
        return self.inner.flush()

    def close(self) -> None:
        """Stop worker and close inner publisher."""
        self._running = False
        self._worker.join(timeout=5.0)
        self.inner.close()

    @property
    def publish_count(self) -> int:
        """Total events published."""
        return self._publish_count

    @property
    def dropped_count(self) -> int:
        """Events dropped due to queue full."""
        return self._dropped_count

    @property
    def queue_size(self) -> int:
        """Current queue size."""
        return self.queue.qsize()


# =============================================================================
# Factory Function
# =============================================================================

def get_event_publisher(config: Dict[str, Any],
                        event_store: Optional[EventStore] = None) -> EventPublisher:
    """
    Factory function to create appropriate EventPublisher.

    Args:
        config: Configuration dictionary
        event_store: Optional EventStore (created if not provided)

    Returns:
        EventPublisher instance
    """
    pub_config = config.get("kaal", {}).get("event_publishing", {})

    publisher_type = pub_config.get("publisher_type", "local")
    async_publish = pub_config.get("async_publish", True)

    # Create event store if not provided
    if event_store is None:
        event_store = get_event_store(config)

    # Create base publisher
    if publisher_type == "kafka":
        bootstrap_servers = pub_config.get("kafka_bootstrap_servers", "localhost:9092")
        topic = pub_config.get("kafka_topic", "rakshak-attack-events")

        base_publisher = KafkaEventPublisher(
            bootstrap_servers=bootstrap_servers,
            topic=topic,
            fallback_store=event_store
        )
    else:
        # Default to local
        base_publisher = LocalEventPublisher(event_store)

    # Wrap with async if requested
    if async_publish:
        queue_size = pub_config.get("queue_size", 1000)
        return AsyncEventPublisher(base_publisher, queue_size=queue_size)

    return base_publisher


# =============================================================================
# Callback-based Event Handlers
# =============================================================================

class EventHandler:
    """
    Callback-based event handler for custom processing.

    Use this to add additional event processing beyond publishing.
    """

    def __init__(self):
        self._handlers: List[Callable[[AttackEvent], None]] = []

    def register(self, handler: Callable[[AttackEvent], None]) -> None:
        """Register an event handler callback."""
        self._handlers.append(handler)
        logger.debug(f"Registered event handler: {handler.__name__}")

    def unregister(self, handler: Callable[[AttackEvent], None]) -> None:
        """Unregister an event handler callback."""
        if handler in self._handlers:
            self._handlers.remove(handler)

    def handle(self, event: AttackEvent) -> None:
        """Call all registered handlers with the event."""
        for handler in self._handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Event handler {handler.__name__} failed: {e}")


# Global event handler instance
_event_handler = EventHandler()


def on_event(handler: Callable[[AttackEvent], None]) -> Callable[[AttackEvent], None]:
    """
    Decorator to register an event handler.

    Usage:
        @on_event
        def my_handler(event: AttackEvent):
            print(f"Got event: {event.event_id}")
    """
    _event_handler.register(handler)
    return handler


def emit_event(event: AttackEvent) -> None:
    """Emit event to all registered handlers."""
    _event_handler.handle(event)
