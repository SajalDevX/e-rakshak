#!/usr/bin/env python3
"""
RAKSHAK Agentic Defender - KAAL
===============================

Knowledge-Augmented Autonomous Learner

A Dueling DQN-based reinforcement learning agent that autonomously
decides defensive actions against cyber threats.

Features:
- Dueling DQN architecture for better action selection
- INFERENCE-ONLY MODE for Jetson deployment (no inline training)
- Event publishing for offline RL training
- Autonomous decision-making without human intervention
- Threat severity-based reward shaping

DEPLOYMENT MODES:
- Inference-Only (default): No training, deterministic decisions, publishes events
- Training Mode: Online learning with experience replay (for development only)

Author: Team RAKSHAK
"""

import os
import random
import numpy as np
from pathlib import Path
from collections import deque
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from loguru import logger

# PyTorch imports
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available - using rule-based fallback")


@dataclass
class Experience:
    """Single experience for replay buffer."""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool


# Only define DuelingDQN if PyTorch is available
if TORCH_AVAILABLE:
    print("Defining DuelingDQN model...")
    class DuelingDQN(nn.Module):
        """
        Dueling Deep Q-Network architecture.

        Separates the network into value and advantage streams,
        then combines them to compute Q-values. This helps the
        agent learn which states are valuable without having to
        learn the effect of each action at that state.

        Architecture:
            Input -> Shared Features -> Value Stream    -> Q(s,a) = V(s) + (A(s,a) - mean(A))
                                     -> Advantage Stream
        """

        def __init__(self, state_size: int = 10, action_size: int = 5, hidden_size: int = 128):
            super().__init__()

            self.state_size = state_size
            self.action_size = action_size
            print(f"Initializing DuelingDQN (state_size={state_size}, action_size={action_size}, hidden_size={hidden_size})")
            # Shared feature extraction layers
            self.feature = nn.Sequential(
                nn.Linear(state_size, hidden_size),
                nn.ReLU(),
                nn.Linear(hidden_size, hidden_size),
                nn.ReLU()
            )

            # Value stream - estimates V(s)
            self.value_stream = nn.Sequential(
                nn.Linear(hidden_size, hidden_size // 2),
                nn.ReLU(),
                nn.Linear(hidden_size // 2, 1)
            )

            # Advantage stream - estimates A(s, a)
            self.advantage_stream = nn.Sequential(
                nn.Linear(hidden_size, hidden_size // 2),
                nn.ReLU(),
                nn.Linear(hidden_size // 2, action_size)
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            """
            Forward pass through the network.

            Combines value and advantage streams using:
            Q(s,a) = V(s) + (A(s,a) - mean(A(s,a)))
            """
            features = self.feature(x)
            value = self.value_stream(features)
            advantage = self.advantage_stream(features)

            # Combine value and advantage
            # Subtract mean advantage to help with identifiability
            q_values = value + (advantage - advantage.mean(dim=1, keepdim=True))

            return q_values
else:
    # Placeholder when PyTorch is not available
    DuelingDQN = None


class ReplayBuffer:
    """Experience replay buffer for stable training."""

    def __init__(self, capacity: int = 10000):
        self.buffer = deque(maxlen=capacity)

    def push(self, experience: Experience):
        """Add experience to buffer."""
        self.buffer.append(experience)

    def sample(self, batch_size: int) -> List[Experience]:
        """Sample random batch of experiences."""
        return random.sample(self.buffer, min(batch_size, len(self.buffer)))

    def __len__(self) -> int:
        return len(self.buffer)


class AgenticDefender:
    """
    KAAL - Knowledge-Augmented Autonomous Learner

    Autonomous defense agent that uses Dueling DQN to decide
    optimal actions in response to detected threats.

    Actions:
        0: MONITOR - Continue observing
        1: DEPLOY_HONEYPOT - Deploy decoy
        2: ISOLATE_DEVICE - Quarantine device
        3: ENGAGE_ATTACKER - Interact via honeypot
        4: ALERT_USER - Send notification
    """

    # Action definitions
    ACTIONS = {
        0: "MONITOR",
        1: "DEPLOY_HONEYPOT",
        2: "ISOLATE_DEVICE",
        3: "ENGAGE_ATTACKER",
        4: "ALERT_USER"
    }

    # Attack type encoding
    ATTACK_TYPES = {
        "port_scan": 0,
        "brute_force": 1,
        "exploit_attempt": 2,
        "dos_attack": 3,
        "malware": 4,
        "data_exfiltration": 5,
        "unauthorized_access": 6,
        "suspicious_traffic": 7
    }

    # Severity encoding
    SEVERITY_LEVELS = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3
    }

    def __init__(self, config: dict, threat_logger=None):
        """
        Initialize the agentic defender.

        Args:
            config: Configuration dictionary
            threat_logger: ThreatLogger instance for action logging
        """
        self.config = config
        self.threat_logger = threat_logger
        self.agent_config = config.get("agent", {})
        self.kaal_config = config.get("kaal", {})

        # =================================================================
        # INFERENCE MODE (Default for Jetson deployment)
        # =================================================================
        # In inference mode:
        # - No training (no backprop, no replay buffer)
        # - Deterministic decisions (epsilon = 0)
        # - Events published for offline RL training
        # =================================================================
        self.inference_only = self.kaal_config.get("inference_only", True)

        # Network parameters
        self.state_size = self.agent_config.get("state_size", 10)
        self.action_size = self.agent_config.get("action_size", 5)
        hidden_layers = self.agent_config.get("hidden_layers", [128, 128])
        self.hidden_size = hidden_layers[0] if hidden_layers else 128

        # Training parameters (only used if inference_only=False)
        self.learning_rate = self.agent_config.get("learning_rate", 0.001)
        self.gamma = self.agent_config.get("gamma", 0.99)
        self.epsilon_end = self.agent_config.get("epsilon_end", 0.01)
        self.epsilon_decay = self.agent_config.get("epsilon_decay", 0.995)
        self.batch_size = self.agent_config.get("batch_size", 64)
        self.target_update = self.agent_config.get("target_update", 10)

        # Epsilon: 0.0 in inference mode (pure greedy), configurable in training
        if self.inference_only:
            self.epsilon = 0.0  # Deterministic decisions
        else:
            self.epsilon = self.agent_config.get("epsilon_start", 1.0)

        # Severity thresholds
        self.severity_thresholds = self.agent_config.get("severity_thresholds", {
            "low": 30,
            "medium": 60,
            "high": 80,
            "critical": 95
        })

        # Initialize model
        self.model_loaded = False

        # Event publisher for offline RL (initialized later if enabled)
        self.event_publisher = None
        self._init_event_publisher()

        if TORCH_AVAILABLE:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self._init_networks()
            mode = "INFERENCE-ONLY" if self.inference_only else "TRAINING"
            logger.info(f"AgenticDefender initialized (mode={mode}, device={self.device})")
        else:
            self.device = None
            logger.warning("PyTorch not available, using rule-based decision making")
            logger.info("AgenticDefender initialized (rule-based mode)")

    def _init_event_publisher(self):
        """Initialize event publisher for offline RL."""
        pub_config = self.kaal_config.get("event_publishing", {})

        if not pub_config.get("enabled", True):
            logger.debug("Event publishing disabled")
            return

        try:
            from .event_bus import get_event_publisher
            from .event_store import get_event_store

            event_store = get_event_store(self.config)
            self.event_publisher = get_event_publisher(self.config, event_store)
            logger.info("Event publisher initialized for offline RL")

        except Exception as e:
            logger.warning(f"Failed to initialize event publisher: {e}")
            self.event_publisher = None

    def _init_networks(self):
        """
        Initialize neural networks.

        In INFERENCE mode:
        - Only policy network loaded (in eval mode)
        - No target network, optimizer, or replay buffer
        - Minimal memory footprint

        In TRAINING mode:
        - Full DQN setup with target network
        - Optimizer and replay buffer initialized
        """
        # Policy network (always needed)
        self.policy_net = DuelingDQN(
            self.state_size,
            self.action_size,
            self.hidden_size
        ).to(self.device)

        if self.inference_only:
            # INFERENCE MODE: Minimal setup
            self.policy_net.eval()  # Set to evaluation mode
            self.target_net = None
            self.optimizer = None
            self.memory = None
            self.steps_done = 0
            self.episodes_done = 0
            logger.debug("Networks initialized in INFERENCE mode (no training components)")
        else:
            # TRAINING MODE: Full DQN setup
            # Target network (for stable training)
            self.target_net = DuelingDQN(
                self.state_size,
                self.action_size,
                self.hidden_size
            ).to(self.device)
            self.target_net.load_state_dict(self.policy_net.state_dict())
            self.target_net.eval()

            # Optimizer
            self.optimizer = optim.Adam(self.policy_net.parameters(), lr=self.learning_rate)

            # Experience replay
            memory_size = self.agent_config.get("memory_size", 10000)
            self.memory = ReplayBuffer(capacity=memory_size)

            # Training step counter
            self.steps_done = 0
            self.episodes_done = 0
            logger.debug("Networks initialized in TRAINING mode")

        # Try to load pre-trained model
        self._load_model()

    def _load_model(self):
        """Load pre-trained model if available."""
        model_path = Path(self.agent_config.get("model_path", "models/dqn_model.pth"))

        if model_path.exists():
            try:
                checkpoint = torch.load(model_path, map_location=self.device)
                self.policy_net.load_state_dict(checkpoint["policy_state_dict"])
                self.target_net.load_state_dict(checkpoint["target_state_dict"])
                self.epsilon = checkpoint.get("epsilon", self.epsilon_end)
                self.steps_done = checkpoint.get("steps_done", 0)
                self.model_loaded = True
                logger.info(f"Loaded pre-trained model from {model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")
        else:
            logger.info("No pre-trained model found, starting fresh")

    def save_model(self, path: str = None):
        """Save current model."""
        if not TORCH_AVAILABLE:
            return

        path = path or self.agent_config.get("model_path", "models/dqn_model.pth")
        model_path = Path(path)
        model_path.parent.mkdir(parents=True, exist_ok=True)

        checkpoint = {
            "policy_state_dict": self.policy_net.state_dict(),
            "target_state_dict": self.target_net.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "epsilon": self.epsilon,
            "steps_done": self.steps_done,
            "episodes_done": self.episodes_done
        }
        torch.save(checkpoint, model_path)
        logger.info(f"Model saved to {model_path}")

    def encode_state(self, threat_info: dict) -> np.ndarray:
        """
        Encode threat information into state vector.

        State features (10-dimensional):
            [0] attack_type (normalized 0-1)
            [1] severity (normalized 0-1)
            [2] source_port / 65535
            [3] target_port / 65535
            [4] packets_per_sec / 1000
            [5] duration (normalized)
            [6] is_known_attacker (0/1)
            [7] device_risk_score / 100
            [8] time_of_day (normalized 0-1)
            [9] protocol_risk (normalized 0-1)
        """
        state = np.zeros(self.state_size, dtype=np.float32)

        # Attack type
        attack_type = threat_info.get("type", "suspicious_traffic")
        state[0] = self.ATTACK_TYPES.get(attack_type, 7) / 7.0

        # Severity
        severity = threat_info.get("severity", "medium")
        state[1] = self.SEVERITY_LEVELS.get(severity, 1) / 3.0

        # Ports
        state[2] = min(threat_info.get("source_port", 0), 65535) / 65535.0
        state[3] = min(threat_info.get("target_port", 0), 65535) / 65535.0

        # Packets per second (capped at 1000)
        packets = threat_info.get("packets_count", 1)
        duration = max(threat_info.get("duration_seconds", 1), 0.1)
        packets_per_sec = packets / duration
        state[4] = min(packets_per_sec, 1000) / 1000.0

        # Duration (capped at 60 seconds)
        state[5] = min(duration, 60) / 60.0

        # Known attacker flag
        state[6] = 1.0 if threat_info.get("known_attacker", False) else 0.0

        # Device risk score
        state[7] = threat_info.get("device_risk_score", 50) / 100.0

        # Time of day (attacks at night might be more suspicious)
        from datetime import datetime
        hour = datetime.now().hour
        state[8] = hour / 24.0

        # Protocol risk
        protocol = threat_info.get("protocol", "tcp").lower()
        protocol_risks = {"tcp": 0.3, "udp": 0.4, "icmp": 0.2}
        state[9] = protocol_risks.get(protocol, 0.5)

        return state

    def decide(self, threat_info: dict) -> dict:
        """
        Decide optimal action for given threat.

        Args:
            threat_info: Dictionary containing threat details

        Returns:
            Dictionary with action and metadata
        """
        if TORCH_AVAILABLE:
            return self._dqn_decide(threat_info)
        else:
            return self._rule_based_decide(threat_info)

    def _dqn_decide(self, threat_info: dict) -> dict:
        """
        Make decision using Dueling DQN.

        In INFERENCE mode:
        - Pure greedy (epsilon = 0)
        - No random exploration
        - Publishes event for offline RL

        In TRAINING mode:
        - Epsilon-greedy exploration
        - Random actions with probability epsilon
        """
        state = self.encode_state(threat_info)
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)

        # Get Q-values (always needed for event publishing)
        with torch.no_grad():
            q_values = self.policy_net(state_tensor)
            q_values_list = q_values[0].cpu().tolist()

        # Action selection
        if self.inference_only or self.epsilon == 0:
            # INFERENCE MODE: Pure greedy (deterministic)
            action = q_values.argmax().item()
            q_value = q_values[0][action].item()
        elif random.random() <= self.epsilon:
            # TRAINING MODE: Random exploration
            action = random.randint(0, self.action_size - 1)
            q_value = q_values[0][action].item()
        else:
            # TRAINING MODE: Greedy selection
            action = q_values.argmax().item()
            q_value = q_values[0][action].item()

        # Get action name
        action_name = self.ACTIONS.get(action, "MONITOR")

        decision = {
            "action": action_name,
            "action_id": action,
            "target": threat_info.get("source_ip", "unknown"),
            "confidence": 1.0 if self.inference_only else (1.0 - self.epsilon),
            "q_value": q_value,
            "q_values": q_values_list,  # All Q-values for analysis
            "status": "decided",
            "inference_mode": self.inference_only
        }

        # Store state for event publishing
        self._last_state = state.tolist()
        self._last_threat_info = threat_info
        self._last_decision = decision

        return decision

    def _publish_decision_event(self, threat_info: dict, state: list,
                                 decision: dict, outcome: str = "monitored",
                                 outcome_success: bool = True,
                                 gateway_mode: bool = False):
        """
        Publish decision event for offline RL training.

        Args:
            threat_info: Original threat information
            state: State vector used for decision
            decision: Decision dictionary
            outcome: Action outcome (monitored, blocked, etc.)
            outcome_success: Whether action succeeded
            gateway_mode: Whether in gateway mode
        """
        if not self.event_publisher:
            return

        try:
            from .event_schema import create_attack_event

            event = create_attack_event(
                threat_info=threat_info,
                state_vector=state,
                decision=decision,
                outcome=outcome,
                outcome_success=outcome_success,
                gateway_mode=gateway_mode
            )

            self.event_publisher.publish(event)
            logger.debug(f"Published decision event: {event.event_id}")

        except Exception as e:
            logger.warning(f"Failed to publish decision event: {e}")

    def _rule_based_decide(self, threat_info: dict) -> dict:
        """Fallback rule-based decision making."""
        severity = threat_info.get("severity", "medium")
        attack_type = threat_info.get("type", "suspicious_traffic")

        # Decision rules
        if severity == "critical":
            action_name = "ISOLATE_DEVICE"
            action_id = 2
        elif severity == "high":
            if attack_type in ["brute_force", "exploit_attempt"]:
                action_name = "ENGAGE_ATTACKER"
                action_id = 3
            else:
                action_name = "DEPLOY_HONEYPOT"
                action_id = 1
        elif severity == "medium":
            action_name = "DEPLOY_HONEYPOT"
            action_id = 1
        else:  # low
            action_name = "MONITOR"
            action_id = 0

        # Always alert on high/critical
        if severity in ["high", "critical"]:
            # Secondary action: alert
            pass

        return {
            "action": action_name,
            "action_id": action_id,
            "target": threat_info.get("source_ip", "unknown"),
            "confidence": 0.8,  # Rule-based confidence
            "q_value": 0.0,
            "status": "decided"
        }

    def train_step(self, state: np.ndarray, action: int, reward: float,
                   next_state: np.ndarray, done: bool):
        """
        Perform one training step.

        NOTE: This method is DISABLED in inference-only mode.
        For Jetson deployment, all training happens offline.

        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Episode ended
        """
        # =================================================================
        # GUARD: No training in inference mode
        # =================================================================
        if self.inference_only:
            logger.debug("train_step called in inference mode - skipping")
            return

        if not TORCH_AVAILABLE:
            return

        if self.memory is None:
            logger.warning("train_step called but replay buffer not initialized")
            return

        # Store experience
        experience = Experience(state, action, reward, next_state, done)
        self.memory.push(experience)

        # Only train if enough samples
        if len(self.memory) < self.batch_size:
            return

        # Sample batch
        batch = self.memory.sample(self.batch_size)

        # Prepare tensors
        states = torch.FloatTensor([e.state for e in batch]).to(self.device)
        actions = torch.LongTensor([e.action for e in batch]).to(self.device)
        rewards = torch.FloatTensor([e.reward for e in batch]).to(self.device)
        next_states = torch.FloatTensor([e.next_state for e in batch]).to(self.device)
        dones = torch.FloatTensor([e.done for e in batch]).to(self.device)

        # Compute Q(s, a)
        current_q = self.policy_net(states).gather(1, actions.unsqueeze(1))

        # Compute Q(s', a') using target network
        with torch.no_grad():
            next_q = self.target_net(next_states).max(1)[0]
            target_q = rewards + (1 - dones) * self.gamma * next_q

        # Compute loss
        loss = F.smooth_l1_loss(current_q.squeeze(), target_q)

        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        # Gradient clipping
        torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
        self.optimizer.step()

        self.steps_done += 1

        # Update target network periodically
        if self.steps_done % self.target_update == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())

        # Decay epsilon
        self.epsilon = max(self.epsilon_end, self.epsilon * self.epsilon_decay)

    def calculate_reward(self, threat_info: dict, action: str, outcome: dict) -> float:
        """
        Calculate reward based on action outcome.

        Reward shaping:
        - High reward for blocking critical threats
        - Negative reward for false positives
        - Small positive reward for information gathering
        """
        severity = threat_info.get("severity", "medium")
        success = outcome.get("success", False)

        # Base rewards by severity
        severity_rewards = {
            "critical": 10.0,
            "high": 5.0,
            "medium": 2.0,
            "low": 0.5
        }
        base = severity_rewards.get(severity, 1.0)

        # Action-specific rewards
        action_rewards = {
            "ISOLATE_DEVICE": base * 2 if success else -5,
            "DEPLOY_HONEYPOT": base * 1.5 if success else -1,
            "ENGAGE_ATTACKER": base * 1.8 if success else -2,
            "ALERT_USER": base * 0.5,
            "MONITOR": base * 0.2
        }

        reward = action_rewards.get(action, 0)

        # Bonus for capturing attacker TTPs
        if outcome.get("ttps_captured", False):
            reward += 3.0

        return reward

    def get_statistics(self) -> dict:
        """Get agent statistics."""
        stats = {
            "steps_done": self.steps_done,
            "episodes_done": self.episodes_done,
            "epsilon": self.epsilon,
            "model_loaded": self.model_loaded,
            "device": str(self.device),
            "inference_only": self.inference_only,
            "mode": "INFERENCE" if self.inference_only else "TRAINING"
        }

        # Memory size only in training mode
        if TORCH_AVAILABLE and self.memory is not None:
            stats["memory_size"] = len(self.memory)
        else:
            stats["memory_size"] = 0

        # Event publisher stats
        if self.event_publisher:
            stats["event_publishing_enabled"] = True
            if hasattr(self.event_publisher, 'publish_count'):
                stats["events_published"] = self.event_publisher.publish_count
        else:
            stats["event_publishing_enabled"] = False

        return stats

    def set_gateway(self, gateway):
        """Set gateway instance for real traffic control."""
        self.gateway = gateway
        logger.info("Gateway integration enabled for real device isolation")

    def set_packet_filter(self, packet_filter):
        """Set packet filter instance for traffic control."""
        self.packet_filter = packet_filter
        logger.info("Packet filter integration enabled")

    def execute_action(self, decision: dict, threat_info: dict, deception_engine=None) -> dict:
        """
        Execute the decided action with real traffic control in gateway mode.

        GATEWAY MODE:
        - ISOLATE_DEVICE: Real iptables DROP rules
        - ENGAGE_ATTACKER: Real NAT redirection to honeypot
        - DEPLOY_HONEYPOT: Honeypot + optional redirection

        STANDALONE MODE:
        - All actions are logged but not enforced
        - Useful for testing/development

        Args:
            decision: Decision from decide() method
            threat_info: Original threat information
            deception_engine: DeceptionEngine instance for honeypot deployment

        Returns:
            Dictionary with execution result
        """
        action = decision.get("action", "MONITOR")
        target_ip = decision.get("target", threat_info.get("source_ip", "unknown"))

        # Determine if we have real traffic control
        has_gateway = hasattr(self, 'gateway') and self.gateway and self.gateway.is_gateway_mode
        has_packet_filter = hasattr(self, 'packet_filter') and self.packet_filter

        result = {
            "action": action,
            "target": target_ip,
            "success": False,
            "message": "",
            "real_action_taken": False,
            "gateway_mode": has_gateway
        }

        try:
            if action == "MONITOR":
                result["success"] = True
                result["message"] = f"Monitoring traffic from {target_ip}"
                logger.info(f"KAAL: Monitoring {target_ip}")

            elif action == "DEPLOY_HONEYPOT":
                if deception_engine:
                    # Use enhanced deploy with redirection in gateway mode
                    if has_gateway and hasattr(deception_engine, 'deploy_honeypot_with_redirect'):
                        honeypot = deception_engine.deploy_honeypot_with_redirect(
                            threat_info=threat_info,
                            protocol="telnet",
                            persona="tp_link"
                        )
                        result["real_action_taken"] = True
                    else:
                        honeypot = deception_engine.deploy_honeypot(
                            protocol="telnet",
                            persona="tp_link"
                        )

                    if honeypot:
                        result["success"] = True
                        result["honeypot_id"] = honeypot.id
                        result["honeypot_port"] = honeypot.port
                        result["message"] = f"Honeypot deployed on port {honeypot.port}"
                        logger.warning(f"KAAL: Deployed honeypot to trap {target_ip}")
                else:
                    result["message"] = "Deception engine not available"

            elif action == "ISOLATE_DEVICE":
                isolated = False
                isolation_method = "none"

                # Method 1: Use gateway (if in gateway mode)
                if has_gateway:
                    try:
                        from core.gateway import IsolationLevel
                        isolated = self.gateway.isolate_device(
                            ip_address=target_ip,
                            level=IsolationLevel.FULL,
                            reason=f"Threat detected: {threat_info.get('type', 'unknown')}"
                        )
                        if isolated:
                            result["real_action_taken"] = True
                            isolation_method = "gateway_iptables"
                            logger.critical(f"KAAL: Device {target_ip} ISOLATED via gateway (REAL)")
                    except Exception as e:
                        logger.error(f"Gateway isolation failed: {e}")

                # Method 2: Use packet filter (iptables) as fallback
                if not isolated and has_packet_filter:
                    try:
                        isolated = self.packet_filter.block_ip(target_ip, "Threat detected by KAAL")
                        if isolated:
                            result["real_action_taken"] = True
                            isolation_method = "packet_filter"
                            logger.critical(f"KAAL: Device {target_ip} BLOCKED via packet filter (REAL)")
                    except Exception as e:
                        logger.error(f"Packet filter block failed: {e}")

                # Method 3: Log-only (standalone mode)
                if not isolated:
                    logger.warning(f"KAAL: Device {target_ip} marked for isolation (SIMULATED)")
                    result["message"] = f"Device {target_ip} isolation requested (no gateway mode)"
                    isolation_method = "simulated"
                else:
                    result["message"] = f"Device {target_ip} has been ISOLATED"

                result["success"] = True
                result["isolation_method"] = isolation_method

            elif action == "ENGAGE_ATTACKER":
                engaged = False
                honeypot_deployed = False

                # Gateway mode: redirect traffic to honeypot
                if has_gateway:
                    # Redirect common attack ports to honeypot
                    for port in [23, 22, 80, 8080]:
                        try:
                            self.gateway.redirect_to_honeypot(
                                source_ip=target_ip,
                                original_port=port,
                                honeypot_port=2323  # Main honeypot port
                            )
                        except Exception as e:
                            logger.debug(f"Redirect setup for port {port}: {e}")
                    engaged = True
                    result["real_action_taken"] = True
                    logger.warning(f"KAAL: Traffic from {target_ip} REDIRECTED to honeypot (REAL)")

                # Deploy honeypot
                if deception_engine:
                    if has_gateway and hasattr(deception_engine, 'deploy_honeypot_with_redirect'):
                        honeypot = deception_engine.deploy_honeypot_with_redirect(
                            threat_info=threat_info,
                            protocol="telnet"
                        )
                    else:
                        honeypot = deception_engine.deploy_honeypot(protocol="telnet")

                    if honeypot:
                        result["honeypot_id"] = honeypot.id
                        result["honeypot_port"] = honeypot.port
                        honeypot_deployed = True

                result["success"] = True
                result["traffic_redirected"] = engaged
                result["honeypot_deployed"] = honeypot_deployed
                result["message"] = f"Engaging attacker {target_ip} via honeypot"

            elif action == "ALERT_USER":
                result["success"] = True
                result["message"] = f"Alert sent for threat from {target_ip}"
                result["alert_severity"] = threat_info.get("severity", "medium")
                logger.warning(f"KAAL: Alert - Threat detected from {target_ip}")

            # Log action to threat logger
            if self.threat_logger:
                self.threat_logger.log_action(
                    action=action,
                    details={
                        "target": target_ip,
                        "threat_type": threat_info.get("type"),
                        "severity": threat_info.get("severity"),
                        "real_action": result["real_action_taken"],
                        "gateway_mode": result["gateway_mode"]
                    },
                    success=result["success"]
                )

            # =================================================================
            # PUBLISH EVENT FOR OFFLINE RL TRAINING
            # =================================================================
            # Map action result to outcome
            outcome_map = {
                "MONITOR": "monitored",
                "DEPLOY_HONEYPOT": "redirected" if result.get("honeypot_id") else "monitored",
                "ISOLATE_DEVICE": "blocked" if result["real_action_taken"] else "monitored",
                "ENGAGE_ATTACKER": "engaged" if result.get("honeypot_deployed") else "redirected",
                "ALERT_USER": "alerted"
            }
            outcome = outcome_map.get(action, "monitored")

            # Publish event with decision context
            if hasattr(self, '_last_state') and hasattr(self, '_last_decision'):
                self._publish_decision_event(
                    threat_info=threat_info,
                    state=self._last_state,
                    decision=self._last_decision,
                    outcome=outcome,
                    outcome_success=result["success"],
                    gateway_mode=has_gateway
                )

        except Exception as e:
            logger.error(f"KAAL: Action execution failed: {e}")
            result["success"] = False
            result["message"] = str(e)

        return result

    def unisolate_device(self, ip_address: str) -> bool:
        """Remove isolation from a device."""
        success = False

        # Try gateway
        if hasattr(self, 'gateway') and self.gateway and self.gateway.is_gateway_mode:
            success = self.gateway.unisolate_device(ip_address)

        # Try packet filter
        if not success and hasattr(self, 'packet_filter') and self.packet_filter:
            success = self.packet_filter.unblock_ip(ip_address)

        if success:
            logger.info(f"KAAL: Device {ip_address} unisolated")
        else:
            logger.warning(f"KAAL: Could not unisolate {ip_address}")

        return success


# Pre-train helper function
def pretrain_agent(config: dict, num_episodes: int = 1000):
    """
    Pre-train agent on simulated threats.

    This creates a baseline model that can be further trained
    during live operation.
    """
    from core.threat_logger import SimulatedThreatGenerator

    agent = AgenticDefender(config)
    generator = SimulatedThreatGenerator(config)

    logger.info(f"Pre-training agent for {num_episodes} episodes...")

    for episode in range(num_episodes):
        # Generate simulated threat
        threat = generator.generate_threat()
        state = agent.encode_state(threat)

        # Take action
        decision = agent.decide(threat)
        action = decision["action_id"]

        # Simulate outcome (random for pre-training)
        success = random.random() > 0.3
        outcome = {"success": success, "ttps_captured": success and random.random() > 0.5}

        # Calculate reward
        reward = agent.calculate_reward(threat, decision["action"], outcome)

        # Next state (simulate threat continuing or stopping)
        done = random.random() > 0.7
        if done:
            next_state = np.zeros(agent.state_size, dtype=np.float32)
        else:
            # Threat might escalate or de-escalate
            threat["severity"] = random.choice(["low", "medium", "high"])
            next_state = agent.encode_state(threat)

        # Train
        agent.train_step(state, action, reward, next_state, done)

        if (episode + 1) % 100 == 0:
            logger.info(f"Episode {episode + 1}/{num_episodes}, Epsilon: {agent.epsilon:.3f}")

    # Save model
    agent.save_model()
    logger.info("Pre-training complete!")

    return agent
