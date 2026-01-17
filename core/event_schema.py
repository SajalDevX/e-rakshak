#!/usr/bin/env python3
"""
RAKSHAK Attack Event Schema
===========================

Defines the AttackEvent dataclass for capturing security decisions.
Used for offline RL training and audit trails.

This module provides:
- AttackEvent: Complete event structure for KAAL decisions
- Serialization to/from JSON for storage and transmission
- Validation utilities

Author: Team RAKSHAK
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum


class ActionType(Enum):
    """KAAL action types."""
    MONITOR = 0
    DEPLOY_HONEYPOT = 1
    ISOLATE_DEVICE = 2
    ENGAGE_ATTACKER = 3
    ALERT_USER = 4


class Severity(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Outcome(Enum):
    """Action outcome types."""
    MONITORED = "monitored"
    BLOCKED = "blocked"
    REDIRECTED = "redirected"
    ENGAGED = "engaged"
    ALERTED = "alerted"
    FAILED = "failed"


@dataclass
class AttackEvent:
    """
    Complete event structure for a KAAL security decision.

    This captures everything needed to:
    1. Audit the decision (who, what, when, why)
    2. Reconstruct RL transitions for offline training
    3. Analyze decision patterns over time

    Attributes:
        event_id: Unique identifier (UUID)
        timestamp: When the event occurred
        source_ip: Attacker's IP address
        target_ip: Target device's IP address
        target_device: Target device name/identifier
        attack_type: Detected attack type (port_scan, brute_force, etc.)
        severity: Threat severity level
        ids_confidence: IDS classifier confidence (0.0-1.0)
        state_vector: 10-dimensional state for KAAL DQN
        action_taken: Action name (MONITOR, ISOLATE_DEVICE, etc.)
        action_id: Action index (0-4)
        q_values: All 5 Q-values from the policy network
        outcome: What happened after the action
        outcome_success: Whether the action achieved its goal
        gateway_mode: Whether RAKSHAK was in gateway mode
        metadata: Additional context (ports, protocol, etc.)
    """

    # Core identifiers
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)

    # Network information
    source_ip: str = ""
    source_port: int = 0
    target_ip: str = ""
    target_port: int = 0
    target_device: str = ""
    protocol: str = "tcp"

    # Threat classification
    attack_type: str = "suspicious_traffic"
    severity: str = "medium"
    ids_confidence: float = 0.0
    ids_attack_type: Optional[str] = None  # Original IDS classification

    # KAAL state and decision
    state_vector: List[float] = field(default_factory=list)
    action_taken: str = "MONITOR"
    action_id: int = 0
    q_values: List[float] = field(default_factory=list)
    decision_confidence: float = 1.0

    # Outcome tracking
    outcome: str = "monitored"
    outcome_success: bool = True
    outcome_details: str = ""

    # System context
    gateway_mode: bool = False
    real_action_taken: bool = False  # Was actual iptables/redirect executed?

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        # Convert datetime to ISO format string
        if isinstance(data["timestamp"], datetime):
            data["timestamp"] = data["timestamp"].isoformat()
        return data

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackEvent":
        """Create AttackEvent from dictionary."""
        # Parse timestamp if string
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> "AttackEvent":
        """Create AttackEvent from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def get_reward(self) -> float:
        """
        Compute reward for offline RL training.

        Reward structure:
        - Base reward from severity
        - Multiplier from action appropriateness
        - Bonus/penalty from outcome
        """
        # Base severity rewards
        severity_rewards = {
            "critical": 10.0,
            "high": 5.0,
            "medium": 2.0,
            "low": 0.5
        }
        base_reward = severity_rewards.get(self.severity, 1.0)

        # Action multipliers (when successful)
        action_multipliers = {
            "ISOLATE_DEVICE": 2.0,
            "ENGAGE_ATTACKER": 1.8,
            "DEPLOY_HONEYPOT": 1.5,
            "ALERT_USER": 0.5,
            "MONITOR": 0.2
        }

        if self.outcome_success:
            multiplier = action_multipliers.get(self.action_taken, 1.0)
            reward = base_reward * multiplier

            # Bonus for capturing TTPs (engaged attacker)
            if self.outcome == "engaged" and self.metadata.get("ttp_captured"):
                reward += 3.0
        else:
            # Penalty for failed actions
            reward = -base_reward * 0.5

        return reward

    def validate(self) -> List[str]:
        """
        Validate event data.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        if not self.event_id:
            errors.append("event_id is required")

        if len(self.state_vector) != 10:
            errors.append(f"state_vector must have 10 elements, got {len(self.state_vector)}")

        if self.action_id not in range(5):
            errors.append(f"action_id must be 0-4, got {self.action_id}")

        if len(self.q_values) != 5 and len(self.q_values) != 0:
            errors.append(f"q_values must have 5 elements or be empty, got {len(self.q_values)}")

        valid_actions = ["MONITOR", "DEPLOY_HONEYPOT", "ISOLATE_DEVICE", "ENGAGE_ATTACKER", "ALERT_USER"]
        if self.action_taken not in valid_actions:
            errors.append(f"action_taken must be one of {valid_actions}")

        valid_severities = ["low", "medium", "high", "critical"]
        if self.severity not in valid_severities:
            errors.append(f"severity must be one of {valid_severities}")

        return errors


@dataclass
class Transition:
    """
    RL transition tuple for offline training.

    Represents (state, action, reward, next_state, done) tuple
    reconstructed from consecutive AttackEvents.
    """
    state: List[float]
    action: int
    reward: float
    next_state: List[float]
    done: bool

    # Source event IDs for traceability
    event_id: str = ""
    next_event_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_events(cls, event: AttackEvent, next_event: Optional[AttackEvent] = None) -> "Transition":
        """
        Create Transition from two consecutive events.

        Args:
            event: Current event
            next_event: Next event (None if terminal)

        Returns:
            Transition tuple for RL training
        """
        return cls(
            state=event.state_vector,
            action=event.action_id,
            reward=event.get_reward(),
            next_state=next_event.state_vector if next_event else [0.0] * 10,
            done=next_event is None,
            event_id=event.event_id,
            next_event_id=next_event.event_id if next_event else ""
        )


# =============================================================================
# Factory Functions
# =============================================================================

def create_attack_event(
    threat_info: Dict[str, Any],
    state_vector: List[float],
    decision: Dict[str, Any],
    outcome: str = "monitored",
    outcome_success: bool = True,
    gateway_mode: bool = False
) -> AttackEvent:
    """
    Factory function to create AttackEvent from KAAL inputs.

    Args:
        threat_info: Threat information dictionary
        state_vector: 10-dimensional state vector
        decision: KAAL decision dictionary
        outcome: Action outcome
        outcome_success: Whether action succeeded
        gateway_mode: Whether in gateway mode

    Returns:
        AttackEvent instance
    """
    return AttackEvent(
        source_ip=threat_info.get("source_ip", "unknown"),
        source_port=threat_info.get("source_port", 0),
        target_ip=threat_info.get("target_ip", "unknown"),
        target_port=threat_info.get("target_port", 0),
        target_device=threat_info.get("target_device", "unknown"),
        protocol=threat_info.get("protocol", "tcp"),
        attack_type=threat_info.get("type", "suspicious_traffic"),
        severity=threat_info.get("severity", "medium"),
        ids_confidence=threat_info.get("confidence", 0.0),
        ids_attack_type=threat_info.get("ids_attack_type"),
        state_vector=state_vector,
        action_taken=decision.get("action", "MONITOR"),
        action_id=decision.get("action_id", 0),
        q_values=decision.get("q_values", []),
        decision_confidence=decision.get("confidence", 1.0),
        outcome=outcome,
        outcome_success=outcome_success,
        gateway_mode=gateway_mode,
        metadata=threat_info.get("metadata", {})
    )


# =============================================================================
# Batch Operations
# =============================================================================

def events_to_transitions(events: List[AttackEvent]) -> List[Transition]:
    """
    Convert a list of events to RL transitions.

    Events are assumed to be in chronological order.
    Each event pairs with the next to form a transition.

    Args:
        events: List of AttackEvents in chronological order

    Returns:
        List of Transition tuples for training
    """
    transitions = []

    for i in range(len(events)):
        next_event = events[i + 1] if i + 1 < len(events) else None
        transition = Transition.from_events(events[i], next_event)
        transitions.append(transition)

    return transitions


def validate_events(events: List[AttackEvent]) -> Dict[str, Any]:
    """
    Validate a batch of events.

    Returns:
        Dictionary with validation results:
        - valid_count: Number of valid events
        - invalid_count: Number of invalid events
        - errors: List of (event_id, errors) tuples
    """
    valid = 0
    invalid = 0
    errors = []

    for event in events:
        event_errors = event.validate()
        if event_errors:
            invalid += 1
            errors.append((event.event_id, event_errors))
        else:
            valid += 1

    return {
        "valid_count": valid,
        "invalid_count": invalid,
        "errors": errors
    }
