#!/usr/bin/env python3
"""
KAAL Offline RL Training Script
===============================

Train the KAAL Dueling DQN agent using offline experience replay
from stored AttackEvents.

This script runs SEPARATELY from the Jetson - typically on a
training machine with GPU. The trained policy is then deployed
to Jetson for inference-only operation.

Usage:
    # Train from JSON event files
    python train_kaal_offline.py --events data/events/*.json --output models/kaal_policy_v2.pth

    # Train from Redis
    python train_kaal_offline.py --redis redis://localhost:6379 --output models/kaal_policy_v2.pth

    # Resume training from existing checkpoint
    python train_kaal_offline.py --events data/events/*.json --resume models/kaal_policy.pth

Author: Team RAKSHAK
"""

import argparse
import glob
import json
import os
import random
import sys
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

import numpy as np

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# PyTorch imports
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    print("ERROR: PyTorch is required for training. Install with: pip install torch")
    sys.exit(1)


# =============================================================================
# Dueling DQN Architecture (same as in agentic_defender.py)
# =============================================================================

class DuelingDQN(nn.Module):
    """
    Dueling Deep Q-Network architecture.

    Separates the network into value and advantage streams,
    then combines them to compute Q-values.
    """

    def __init__(self, state_size: int = 10, action_size: int = 5, hidden_size: int = 128):
        super().__init__()

        self.state_size = state_size
        self.action_size = action_size

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
        """Forward pass through the network."""
        features = self.feature(x)
        value = self.value_stream(features)
        advantage = self.advantage_stream(features)

        # Combine: Q(s,a) = V(s) + (A(s,a) - mean(A))
        q_values = value + (advantage - advantage.mean(dim=1, keepdim=True))
        return q_values


# =============================================================================
# Transition and Replay Buffer
# =============================================================================

@dataclass
class Transition:
    """RL transition tuple."""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool


class ReplayBuffer:
    """Experience replay buffer."""

    def __init__(self, capacity: int = 100000):
        self.buffer = deque(maxlen=capacity)

    def push(self, transition: Transition):
        """Add transition to buffer."""
        self.buffer.append(transition)

    def sample(self, batch_size: int) -> List[Transition]:
        """Sample random batch."""
        return random.sample(self.buffer, min(batch_size, len(self.buffer)))

    def __len__(self) -> int:
        return len(self.buffer)


# =============================================================================
# Event Loading
# =============================================================================

def load_events_from_json(path: str) -> List[Dict]:
    """Load events from a JSON file."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)

        # Handle both formats: {"events": [...]} and [...]
        if isinstance(data, dict) and "events" in data:
            return data["events"]
        elif isinstance(data, list):
            return data
        else:
            print(f"WARNING: Unknown format in {path}")
            return []

    except Exception as e:
        print(f"ERROR loading {path}: {e}")
        return []


def load_events_from_directory(pattern: str) -> List[Dict]:
    """Load events from multiple JSON files matching pattern."""
    all_events = []

    for filepath in glob.glob(pattern):
        events = load_events_from_json(filepath)
        all_events.extend(events)
        print(f"  Loaded {len(events)} events from {filepath}")

    # Sort by timestamp
    all_events.sort(key=lambda e: e.get("timestamp", ""))

    return all_events


def load_events_from_redis(redis_url: str, key: str = "rakshak:attack_events") -> List[Dict]:
    """Load events from Redis."""
    try:
        import redis
        client = redis.from_url(redis_url)

        raw_events = client.lrange(key, 0, -1)
        events = []

        for raw in raw_events:
            try:
                event = json.loads(raw.decode('utf-8'))
                events.append(event)
            except:
                pass

        # Reverse to get chronological order
        events.reverse()
        print(f"  Loaded {len(events)} events from Redis")
        return events

    except Exception as e:
        print(f"ERROR loading from Redis: {e}")
        return []


# =============================================================================
# Reward Computation
# =============================================================================

def compute_reward(event: Dict) -> float:
    """
    Compute reward for an event based on outcome and severity.

    Reward shaping:
    - High reward for blocking critical threats
    - Medium reward for engaging attackers (intel gathering)
    - Low reward for monitoring
    - Negative reward for failed actions
    """
    severity = event.get("severity", "medium")
    action = event.get("action_taken", "MONITOR")
    outcome_success = event.get("outcome_success", True)

    # Base severity rewards
    severity_rewards = {
        "critical": 10.0,
        "high": 5.0,
        "medium": 2.0,
        "low": 0.5
    }
    base = severity_rewards.get(severity, 1.0)

    # Action multipliers
    action_multipliers = {
        "ISOLATE_DEVICE": 2.0,
        "ENGAGE_ATTACKER": 1.8,
        "DEPLOY_HONEYPOT": 1.5,
        "ALERT_USER": 0.5,
        "MONITOR": 0.2
    }

    if outcome_success:
        multiplier = action_multipliers.get(action, 1.0)
        reward = base * multiplier

        # Bonus for TTP capture
        if event.get("metadata", {}).get("ttp_captured"):
            reward += 3.0
    else:
        # Penalty for failed actions
        reward = -base * 0.5

    return reward


# =============================================================================
# Transition Building
# =============================================================================

def build_transitions(events: List[Dict]) -> List[Transition]:
    """
    Convert events to RL transitions.

    Each event becomes a transition:
    - state: state_vector from event
    - action: action_id from event
    - reward: computed reward
    - next_state: state_vector from next event (or zeros if terminal)
    - done: True if no next event or attack ended
    """
    transitions = []

    for i, event in enumerate(events):
        # Extract state
        state = event.get("state_vector", [0.0] * 10)
        if len(state) != 10:
            print(f"WARNING: Invalid state vector length {len(state)}, skipping")
            continue

        state = np.array(state, dtype=np.float32)

        # Extract action
        action = event.get("action_id", 0)

        # Compute reward
        reward = compute_reward(event)

        # Get next state
        if i + 1 < len(events):
            next_event = events[i + 1]
            next_state = next_event.get("state_vector", [0.0] * 10)

            # Check if same attack continues (based on source_ip)
            same_attack = (
                event.get("source_ip") == next_event.get("source_ip") and
                (datetime.fromisoformat(next_event.get("timestamp", "2000-01-01")) -
                 datetime.fromisoformat(event.get("timestamp", "2000-01-01"))).seconds < 300
            )
            done = not same_attack
        else:
            next_state = [0.0] * 10
            done = True

        next_state = np.array(next_state, dtype=np.float32)

        transitions.append(Transition(
            state=state,
            action=action,
            reward=reward,
            next_state=next_state,
            done=done
        ))

    return transitions


# =============================================================================
# Offline Training
# =============================================================================

def train_offline(
    transitions: List[Transition],
    output_path: str,
    resume_path: Optional[str] = None,
    epochs: int = 100,
    batch_size: int = 64,
    learning_rate: float = 0.001,
    gamma: float = 0.99,
    target_update: int = 10,
    device: str = "auto"
) -> DuelingDQN:
    """
    Train Dueling DQN using offline experience replay.

    Args:
        transitions: List of Transition tuples
        output_path: Path to save trained model
        resume_path: Path to checkpoint to resume from
        epochs: Number of training epochs
        batch_size: Batch size for training
        learning_rate: Learning rate
        gamma: Discount factor
        target_update: Update target network every N epochs
        device: "cuda", "cpu", or "auto"

    Returns:
        Trained DuelingDQN model
    """
    # Device selection
    if device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    device = torch.device(device)
    print(f"\nUsing device: {device}")

    # Initialize networks
    state_size = 10
    action_size = 5

    policy_net = DuelingDQN(state_size, action_size).to(device)
    target_net = DuelingDQN(state_size, action_size).to(device)

    # Load checkpoint if resuming
    if resume_path and os.path.exists(resume_path):
        print(f"Loading checkpoint from {resume_path}")
        checkpoint = torch.load(resume_path, map_location=device)
        policy_net.load_state_dict(checkpoint["policy_state_dict"])
        target_net.load_state_dict(checkpoint.get("target_state_dict", checkpoint["policy_state_dict"]))
        start_epoch = checkpoint.get("epoch", 0)
        print(f"Resumed from epoch {start_epoch}")
    else:
        target_net.load_state_dict(policy_net.state_dict())
        start_epoch = 0

    target_net.eval()

    # Optimizer
    optimizer = optim.Adam(policy_net.parameters(), lr=learning_rate)

    # Load transitions into replay buffer
    print(f"\nLoading {len(transitions)} transitions into replay buffer...")
    replay_buffer = ReplayBuffer(capacity=len(transitions) + 10000)
    for t in transitions:
        replay_buffer.push(t)

    if len(replay_buffer) < batch_size:
        print(f"ERROR: Not enough transitions ({len(replay_buffer)}) for batch size ({batch_size})")
        return policy_net

    # Training loop
    print(f"\n{'='*60}")
    print(f"Starting Offline RL Training")
    print(f"{'='*60}")
    print(f"Epochs: {epochs}")
    print(f"Batch size: {batch_size}")
    print(f"Learning rate: {learning_rate}")
    print(f"Gamma: {gamma}")
    print(f"Transitions: {len(transitions)}")
    print(f"{'='*60}\n")

    losses = []
    best_loss = float('inf')

    for epoch in range(start_epoch, start_epoch + epochs):
        epoch_losses = []

        # Multiple training steps per epoch
        steps_per_epoch = max(1, len(transitions) // batch_size)

        for step in range(steps_per_epoch):
            # Sample batch
            batch = replay_buffer.sample(batch_size)

            # Prepare tensors
            states = torch.FloatTensor([t.state for t in batch]).to(device)
            actions = torch.LongTensor([t.action for t in batch]).to(device)
            rewards = torch.FloatTensor([t.reward for t in batch]).to(device)
            next_states = torch.FloatTensor([t.next_state for t in batch]).to(device)
            dones = torch.FloatTensor([float(t.done) for t in batch]).to(device)

            # Compute Q(s, a)
            current_q = policy_net(states).gather(1, actions.unsqueeze(1))

            # Compute target Q using Double DQN
            with torch.no_grad():
                # Select actions using policy network
                next_actions = policy_net(next_states).argmax(1, keepdim=True)
                # Evaluate using target network
                next_q = target_net(next_states).gather(1, next_actions).squeeze(1)
                target_q = rewards + (1 - dones) * gamma * next_q

            # Compute loss (Huber loss for stability)
            loss = F.smooth_l1_loss(current_q.squeeze(), target_q)

            # Optimize
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(policy_net.parameters(), 1.0)
            optimizer.step()

            epoch_losses.append(loss.item())

        # Epoch statistics
        avg_loss = np.mean(epoch_losses)
        losses.append(avg_loss)

        # Update target network
        if (epoch + 1) % target_update == 0:
            target_net.load_state_dict(policy_net.state_dict())

        # Progress output
        if (epoch + 1) % 10 == 0 or epoch == start_epoch:
            print(f"Epoch {epoch + 1:4d}/{start_epoch + epochs} | Loss: {avg_loss:.6f} | Steps: {steps_per_epoch}")

        # Save best model
        if avg_loss < best_loss:
            best_loss = avg_loss

    # Save final model
    print(f"\n{'='*60}")
    print(f"Training Complete!")
    print(f"{'='*60}")
    print(f"Final Loss: {losses[-1]:.6f}")
    print(f"Best Loss: {best_loss:.6f}")

    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Save checkpoint
    checkpoint = {
        "policy_state_dict": policy_net.state_dict(),
        "target_state_dict": target_net.state_dict(),
        "optimizer_state_dict": optimizer.state_dict(),
        "epoch": start_epoch + epochs,
        "loss": losses[-1],
        "best_loss": best_loss,
        "training_info": {
            "transitions": len(transitions),
            "epochs": epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "gamma": gamma,
            "timestamp": datetime.now().isoformat()
        }
    }

    torch.save(checkpoint, output_path)
    print(f"\nModel saved to: {output_path}")

    # Also save inference-only version (smaller file)
    inference_path = output_path.replace(".pth", "_inference.pth")
    torch.save({
        "policy_state_dict": policy_net.state_dict(),
        "state_size": state_size,
        "action_size": action_size
    }, inference_path)
    print(f"Inference model saved to: {inference_path}")

    return policy_net


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="KAAL Offline RL Training",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train from JSON event files
  python train_kaal_offline.py --events "data/events/*.json"

  # Train from Redis
  python train_kaal_offline.py --redis redis://localhost:6379

  # Resume training
  python train_kaal_offline.py --events "data/events/*.json" --resume models/kaal_policy.pth

  # Custom training parameters
  python train_kaal_offline.py --events "data/events/*.json" --epochs 200 --batch-size 128
        """
    )

    # Data source (mutually exclusive)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--events", type=str, help="Glob pattern for JSON event files")
    source.add_argument("--redis", type=str, help="Redis URL (redis://host:port)")

    # Output
    parser.add_argument("--output", "-o", type=str, default="models/kaal_policy.pth",
                        help="Output path for trained model (default: models/kaal_policy.pth)")

    # Resume training
    parser.add_argument("--resume", type=str, help="Path to checkpoint to resume from")

    # Training parameters
    parser.add_argument("--epochs", type=int, default=100, help="Number of epochs (default: 100)")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size (default: 64)")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate (default: 0.001)")
    parser.add_argument("--gamma", type=float, default=0.99, help="Discount factor (default: 0.99)")
    parser.add_argument("--target-update", type=int, default=10, help="Target network update interval (default: 10)")

    # Device
    parser.add_argument("--device", type=str, default="auto",
                        choices=["auto", "cuda", "cpu"], help="Device (default: auto)")

    args = parser.parse_args()

    print("=" * 60)
    print("KAAL Offline RL Training")
    print("=" * 60)
    print(f"Time: {datetime.now().isoformat()}")
    print()

    # Load events
    print("Loading events...")
    if args.events:
        events = load_events_from_directory(args.events)
    else:
        events = load_events_from_redis(args.redis)

    if not events:
        print("ERROR: No events loaded. Check your data source.")
        sys.exit(1)

    print(f"Total events loaded: {len(events)}")

    # Build transitions
    print("\nBuilding transitions...")
    transitions = build_transitions(events)
    print(f"Total transitions: {len(transitions)}")

    if not transitions:
        print("ERROR: No valid transitions built from events.")
        sys.exit(1)

    # Analyze transitions
    actions = [t.action for t in transitions]
    rewards = [t.reward for t in transitions]
    print(f"\nTransition Statistics:")
    print(f"  Actions distribution: {dict(zip(*np.unique(actions, return_counts=True)))}")
    print(f"  Reward mean: {np.mean(rewards):.2f}, std: {np.std(rewards):.2f}")
    print(f"  Reward range: [{min(rewards):.2f}, {max(rewards):.2f}]")

    # Train
    model = train_offline(
        transitions=transitions,
        output_path=args.output,
        resume_path=args.resume,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        gamma=args.gamma,
        target_update=args.target_update,
        device=args.device
    )

    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)
    print(f"\nTo deploy the trained model to Jetson:")
    print(f"  scp {args.output} user@jetson:~/e-raksha/models/kaal_policy.pth")
    print(f"\nOr for inference-only deployment:")
    print(f"  scp {args.output.replace('.pth', '_inference.pth')} user@jetson:~/e-raksha/models/")


if __name__ == "__main__":
    main()
