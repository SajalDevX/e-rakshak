#!/usr/bin/env python3
"""
KAAL Model Training Script
==========================

Train the KAAL (Knowledge-Augmented Autonomous Learner) Dueling DQN model
using the CICIDS2017 intrusion detection dataset.

Dataset: https://www.kaggle.com/datasets/mdalamintalukder/cicids2017

Usage:
    python scripts/train_kaal.py --data_dir data/cicids2017 --epochs 100

Author: Team RAKSHAK
"""

import os
import sys
import argparse
import random
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import deque
from datetime import datetime

import numpy as np
import pandas as pd
from tqdm import tqdm

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# PyTorch imports
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader


# =============================================================================
# CICIDS2017 to KAAL Mapping
# =============================================================================

# CICIDS2017 attack labels to KAAL attack types
CICIDS_TO_KAAL_ATTACK = {
    # Benign
    "BENIGN": "normal",

    # DoS attacks
    "DoS Hulk": "dos_attack",
    "DoS GoldenEye": "dos_attack",
    "DoS slowloris": "dos_attack",
    "DoS Slowhttptest": "dos_attack",
    "Heartbleed": "dos_attack",

    # DDoS
    "DDoS": "dos_attack",

    # Port scanning
    "PortScan": "port_scan",

    # Brute force
    "FTP-Patator": "brute_force",
    "SSH-Patator": "brute_force",

    # Web attacks
    "Web Attack – Brute Force": "brute_force",
    "Web Attack – XSS": "exploit_attempt",
    "Web Attack – Sql Injection": "exploit_attempt",

    # Infiltration
    "Infiltration": "malware",

    # Botnet
    "Bot": "malware",
}

# KAAL attack type encoding (from agentic_defender.py)
ATTACK_TYPE_ENCODING = {
    "normal": -1,  # Not an attack
    "port_scan": 0,
    "brute_force": 1,
    "exploit_attempt": 2,
    "dos_attack": 3,
    "malware": 4,
    "data_exfiltration": 5,
    "unauthorized_access": 6,
    "suspicious_traffic": 7
}

# Severity mapping based on attack type
ATTACK_SEVERITY = {
    "normal": "low",
    "port_scan": "low",
    "brute_force": "high",
    "exploit_attempt": "critical",
    "dos_attack": "high",
    "malware": "critical",
    "data_exfiltration": "critical",
    "unauthorized_access": "high",
    "suspicious_traffic": "medium"
}

SEVERITY_ENCODING = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3
}

# Optimal action for each attack type (supervised labels)
OPTIMAL_ACTIONS = {
    "normal": 0,           # MONITOR
    "port_scan": 1,        # DEPLOY_HONEYPOT (gather intel)
    "brute_force": 3,      # ENGAGE_ATTACKER (via honeypot)
    "exploit_attempt": 2,  # ISOLATE_DEVICE (critical)
    "dos_attack": 2,       # ISOLATE_DEVICE (block flood)
    "malware": 2,          # ISOLATE_DEVICE (critical)
    "data_exfiltration": 2, # ISOLATE_DEVICE (stop leak)
    "unauthorized_access": 3, # ENGAGE_ATTACKER
    "suspicious_traffic": 1   # DEPLOY_HONEYPOT
}


# =============================================================================
# Dueling DQN Model (same as in agentic_defender.py)
# =============================================================================

class DuelingDQN(nn.Module):
    """Dueling Deep Q-Network architecture."""

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

        # Combine value and advantage
        q_values = value + (advantage - advantage.mean(dim=1, keepdim=True))
        return q_values


# =============================================================================
# Dataset Class
# =============================================================================

class CICIDS2017Dataset(Dataset):
    """
    PyTorch Dataset for CICIDS2017 data.

    Converts CICIDS2017 features to KAAL 10-dimensional state vectors.
    """

    def __init__(self, data_dir: str, max_samples: int = None, balance_classes: bool = True):
        """
        Load and preprocess CICIDS2017 dataset.

        Args:
            data_dir: Directory containing CICIDS2017 CSV files
            max_samples: Maximum samples to load (for memory efficiency)
            balance_classes: Undersample majority class to balance
        """
        self.data_dir = Path(data_dir)
        self.samples = []
        self.labels = []

        print(f"Loading CICIDS2017 data from {data_dir}...")

        # Find all CSV files
        csv_files = list(self.data_dir.glob("*.csv"))
        if not csv_files:
            raise ValueError(f"No CSV files found in {data_dir}")

        print(f"Found {len(csv_files)} CSV files")

        all_data = []
        for csv_file in tqdm(csv_files, desc="Loading CSV files"):
            try:
                df = pd.read_csv(csv_file, low_memory=False)
                # Clean column names (remove leading/trailing spaces)
                df.columns = df.columns.str.strip()
                all_data.append(df)
            except Exception as e:
                print(f"Error loading {csv_file}: {e}")
                continue

        if not all_data:
            raise ValueError("No data loaded!")

        # Combine all data
        df = pd.concat(all_data, ignore_index=True)
        print(f"Total samples: {len(df)}")

        # Show label distribution
        label_col = self._find_label_column(df)
        print(f"\nLabel distribution:")
        print(df[label_col].value_counts())

        # Balance classes if requested
        if balance_classes:
            df = self._balance_dataset(df, label_col)
            print(f"\nAfter balancing: {len(df)} samples")

        # Limit samples if specified
        if max_samples and len(df) > max_samples:
            df = df.sample(n=max_samples, random_state=42)
            print(f"Sampled {max_samples} rows")

        # Convert to KAAL states
        print("\nConverting to KAAL state vectors...")
        for idx, row in tqdm(df.iterrows(), total=len(df), desc="Processing"):
            try:
                state, attack_type = self._convert_row_to_state(row, label_col)
                optimal_action = OPTIMAL_ACTIONS.get(attack_type, 0)

                self.samples.append(state)
                self.labels.append(optimal_action)
            except Exception as e:
                continue

        print(f"\nProcessed {len(self.samples)} valid samples")

        # Convert to numpy arrays
        self.samples = np.array(self.samples, dtype=np.float32)
        self.labels = np.array(self.labels, dtype=np.int64)

    def _find_label_column(self, df: pd.DataFrame) -> str:
        """Find the label column in the dataset."""
        possible_names = ['Label', 'label', ' Label', 'Attack', 'attack']
        for name in possible_names:
            if name in df.columns:
                return name
        raise ValueError(f"Could not find label column. Columns: {df.columns.tolist()}")

    def _balance_dataset(self, df: pd.DataFrame, label_col: str) -> pd.DataFrame:
        """Balance dataset by undersampling majority class."""
        # Get class counts
        class_counts = df[label_col].value_counts()

        # Find minimum count (excluding very small classes)
        min_count = class_counts[class_counts > 100].min()
        target_count = min(min_count, 50000)  # Cap at 50k per class

        balanced_dfs = []
        for label in df[label_col].unique():
            label_df = df[df[label_col] == label]
            if len(label_df) > target_count:
                label_df = label_df.sample(n=target_count, random_state=42)
            balanced_dfs.append(label_df)

        return pd.concat(balanced_dfs, ignore_index=True)

    def _convert_row_to_state(self, row: pd.Series, label_col: str) -> Tuple[np.ndarray, str]:
        """
        Convert a CICIDS2017 row to KAAL 10-dimensional state.

        KAAL State features:
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
        state = np.zeros(10, dtype=np.float32)

        # Get attack type
        cicids_label = str(row[label_col]).strip()
        attack_type = CICIDS_TO_KAAL_ATTACK.get(cicids_label, "suspicious_traffic")

        # [0] Attack type (normalized)
        attack_encoding = ATTACK_TYPE_ENCODING.get(attack_type, 7)
        state[0] = max(0, attack_encoding) / 7.0  # -1 (normal) becomes 0

        # [1] Severity
        severity = ATTACK_SEVERITY.get(attack_type, "medium")
        state[1] = SEVERITY_ENCODING.get(severity, 1) / 3.0

        # [2] Source port
        src_port = self._safe_get(row, ['Source Port', ' Source Port', 'Src Port'], 0)
        state[2] = min(float(src_port), 65535) / 65535.0

        # [3] Destination port
        dst_port = self._safe_get(row, ['Destination Port', ' Destination Port', 'Dst Port'], 0)
        state[3] = min(float(dst_port), 65535) / 65535.0

        # [4] Packets per second
        total_fwd = self._safe_get(row, ['Total Fwd Packets', ' Total Fwd Packets'], 0)
        total_bwd = self._safe_get(row, ['Total Backward Packets', ' Total Backward Packets'], 0)
        duration = self._safe_get(row, ['Flow Duration', ' Flow Duration'], 1)
        duration_sec = max(float(duration) / 1000000, 0.001)  # Convert to seconds
        packets = float(total_fwd) + float(total_bwd)
        packets_per_sec = packets / duration_sec
        state[4] = min(packets_per_sec, 1000) / 1000.0

        # [5] Duration (normalized, capped at 60 seconds)
        state[5] = min(duration_sec, 60) / 60.0

        # [6] Known attacker (simulate based on attack type)
        state[6] = 1.0 if attack_type in ["malware", "brute_force"] else 0.0

        # [7] Device risk score (derived from flow characteristics)
        fwd_psh = self._safe_get(row, ['Fwd PSH Flags', ' Fwd PSH Flags'], 0)
        bwd_psh = self._safe_get(row, ['Bwd PSH Flags', ' Bwd PSH Flags'], 0)
        syn_count = self._safe_get(row, ['SYN Flag Count', ' SYN Flag Count'], 0)
        risk_score = min((float(fwd_psh) + float(bwd_psh) + float(syn_count)) * 10, 100)
        state[7] = risk_score / 100.0

        # [8] Time of day (random for training, real-time in deployment)
        state[8] = random.random()  # Simulated

        # [9] Protocol risk
        protocol = self._safe_get(row, ['Protocol', ' Protocol'], 6)  # 6=TCP
        protocol_risks = {6: 0.3, 17: 0.4, 1: 0.2}  # TCP, UDP, ICMP
        state[9] = protocol_risks.get(int(protocol), 0.5)

        return state, attack_type

    def _safe_get(self, row: pd.Series, keys: List[str], default: float) -> float:
        """Safely get a value from row with multiple possible column names."""
        for key in keys:
            if key in row.index:
                try:
                    val = row[key]
                    if pd.isna(val) or val == 'Infinity' or val == '-Infinity':
                        return default
                    return float(val)
                except:
                    return default
        return default

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx], self.labels[idx]


# =============================================================================
# Replay Buffer
# =============================================================================

class ReplayBuffer:
    """Experience replay buffer for RL training."""

    def __init__(self, capacity: int = 10000):
        self.buffer = deque(maxlen=capacity)

    def push(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size: int):
        batch = random.sample(self.buffer, min(batch_size, len(self.buffer)))
        states, actions, rewards, next_states, dones = zip(*batch)
        return (
            np.array(states),
            np.array(actions),
            np.array(rewards),
            np.array(next_states),
            np.array(dones)
        )

    def __len__(self):
        return len(self.buffer)


# =============================================================================
# Training Functions
# =============================================================================

def train_supervised(model: DuelingDQN, dataset: CICIDS2017Dataset,
                    epochs: int = 100, batch_size: int = 64,
                    learning_rate: float = 0.001, device: str = "cuda"):
    """
    Phase 1: Supervised pre-training using CICIDS2017 labels.

    This trains the model to predict the "optimal" action for each attack type,
    giving it a good starting point before RL fine-tuning.
    """
    print("\n" + "="*60)
    print("PHASE 1: SUPERVISED PRE-TRAINING")
    print("="*60)

    device = torch.device(device if torch.cuda.is_available() else "cpu")
    model = model.to(device)

    # Create data loader
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, num_workers=4)

    # Optimizer and loss
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.CrossEntropyLoss()

    # Training loop
    model.train()
    best_accuracy = 0.0

    for epoch in range(epochs):
        total_loss = 0
        correct = 0
        total = 0

        pbar = tqdm(loader, desc=f"Epoch {epoch+1}/{epochs}")
        for states, labels in pbar:
            states = states.to(device)
            labels = labels.to(device)

            # Forward pass
            q_values = model(states)

            # Loss (cross-entropy on Q-values as logits)
            loss = criterion(q_values, labels)

            # Backward pass
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            # Metrics
            total_loss += loss.item()
            _, predicted = q_values.max(1)
            correct += predicted.eq(labels).sum().item()
            total += labels.size(0)

            pbar.set_postfix({
                'loss': f'{loss.item():.4f}',
                'acc': f'{100.*correct/total:.2f}%'
            })

        # Epoch summary
        epoch_loss = total_loss / len(loader)
        epoch_acc = 100. * correct / total

        print(f"Epoch {epoch+1}: Loss={epoch_loss:.4f}, Accuracy={epoch_acc:.2f}%")

        # Save best model
        if epoch_acc > best_accuracy:
            best_accuracy = epoch_acc
            torch.save({
                'policy_state_dict': model.state_dict(),
                'target_state_dict': model.state_dict(),
                'epoch': epoch,
                'accuracy': epoch_acc,
                'epsilon': 0.1,  # Low epsilon after supervised training
                'steps_done': epoch * len(loader)
            }, 'models/dqn_model_supervised.pth')
            print(f"  → Saved best model (accuracy: {epoch_acc:.2f}%)")

    return model, best_accuracy


def train_rl(model: DuelingDQN, dataset: CICIDS2017Dataset,
             episodes: int = 10000, batch_size: int = 64,
             gamma: float = 0.99, epsilon_start: float = 0.3,
             epsilon_end: float = 0.01, epsilon_decay: float = 0.995,
             device: str = "cuda"):
    """
    Phase 2: Reinforcement learning fine-tuning.

    Uses the supervised pre-trained model and further trains with RL
    using simulated rewards.
    """
    print("\n" + "="*60)
    print("PHASE 2: REINFORCEMENT LEARNING FINE-TUNING")
    print("="*60)

    device = torch.device(device if torch.cuda.is_available() else "cpu")
    model = model.to(device)

    # Create target network
    target_model = DuelingDQN(10, 5, 128).to(device)
    target_model.load_state_dict(model.state_dict())
    target_model.eval()

    # Optimizer
    optimizer = optim.Adam(model.parameters(), lr=0.0001)  # Lower LR for fine-tuning

    # Replay buffer
    memory = ReplayBuffer(capacity=50000)

    # Fill replay buffer with dataset experiences
    print("Filling replay buffer...")
    for i in tqdm(range(len(dataset)), desc="Building replay buffer"):
        state, optimal_action = dataset[i]

        # Simulate taking action and getting reward
        action = optimal_action  # Use optimal action
        reward = calculate_reward(state, action)

        # Next state (simulate small perturbation)
        next_state = state + np.random.normal(0, 0.01, state.shape).astype(np.float32)
        next_state = np.clip(next_state, 0, 1)

        # Done flag (random)
        done = random.random() > 0.9

        memory.push(state, action, reward, next_state, done)

    print(f"Replay buffer size: {len(memory)}")

    # RL Training loop
    epsilon = epsilon_start
    target_update = 100

    for episode in range(episodes):
        # Sample random state from dataset
        idx = random.randint(0, len(dataset) - 1)
        state, _ = dataset[idx]

        # Epsilon-greedy action selection
        if random.random() < epsilon:
            action = random.randint(0, 4)
        else:
            state_tensor = torch.FloatTensor(state).unsqueeze(0).to(device)
            with torch.no_grad():
                q_values = model(state_tensor)
                action = q_values.argmax().item()

        # Simulate environment response
        reward = calculate_reward(state, action)
        next_state = state + np.random.normal(0, 0.01, state.shape).astype(np.float32)
        next_state = np.clip(next_state, 0, 1)
        done = random.random() > 0.9

        # Store experience
        memory.push(state, action, reward, next_state, done)

        # Train if enough samples
        if len(memory) >= batch_size:
            # Sample batch
            states, actions, rewards, next_states, dones = memory.sample(batch_size)

            states = torch.FloatTensor(states).to(device)
            actions = torch.LongTensor(actions).to(device)
            rewards = torch.FloatTensor(rewards).to(device)
            next_states = torch.FloatTensor(next_states).to(device)
            dones = torch.FloatTensor(dones).to(device)

            # Compute Q(s, a)
            current_q = model(states).gather(1, actions.unsqueeze(1))

            # Compute target Q
            with torch.no_grad():
                next_q = target_model(next_states).max(1)[0]
                target_q = rewards + (1 - dones) * gamma * next_q

            # Loss
            loss = F.smooth_l1_loss(current_q.squeeze(), target_q)

            # Optimize
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

        # Update target network
        if episode % target_update == 0:
            target_model.load_state_dict(model.state_dict())

        # Decay epsilon
        epsilon = max(epsilon_end, epsilon * epsilon_decay)

        # Progress
        if (episode + 1) % 1000 == 0:
            print(f"Episode {episode+1}/{episodes}, Epsilon: {epsilon:.4f}")

    # Save final model
    torch.save({
        'policy_state_dict': model.state_dict(),
        'target_state_dict': target_model.state_dict(),
        'epsilon': epsilon,
        'steps_done': episodes
    }, 'models/dqn_model.pth')

    print("\nRL training complete! Model saved to models/dqn_model.pth")
    return model


def calculate_reward(state: np.ndarray, action: int) -> float:
    """
    Calculate reward based on state and action.

    Rewards:
    - High reward for appropriate action given severity
    - Negative reward for over-reaction to benign traffic
    - Positive reward for blocking critical threats
    """
    attack_type = state[0] * 7  # De-normalize
    severity = state[1] * 3

    # Severity rewards
    severity_multiplier = {0: 0.5, 1: 1.0, 2: 2.0, 3: 3.0}
    base_reward = severity_multiplier.get(int(severity), 1.0)

    # Action appropriateness
    if attack_type < 0.1:  # Normal traffic
        if action == 0:  # MONITOR
            return 1.0  # Correct: monitor normal traffic
        else:
            return -2.0  # Penalty for over-reacting

    elif severity >= 2:  # High/Critical
        if action == 2:  # ISOLATE_DEVICE
            return base_reward * 3.0  # High reward for isolation
        elif action == 3:  # ENGAGE_ATTACKER
            return base_reward * 2.0  # Good for intelligence
        else:
            return base_reward * 0.5

    elif severity >= 1:  # Medium
        if action == 1:  # DEPLOY_HONEYPOT
            return base_reward * 2.0
        elif action == 3:  # ENGAGE_ATTACKER
            return base_reward * 1.5
        else:
            return base_reward * 0.5

    else:  # Low
        if action == 0:  # MONITOR
            return base_reward * 1.5
        elif action == 4:  # ALERT_USER
            return base_reward * 1.0
        else:
            return base_reward * 0.3

    return 0.0


def evaluate_model(model: DuelingDQN, dataset: CICIDS2017Dataset, device: str = "cuda"):
    """Evaluate model accuracy on dataset."""
    print("\n" + "="*60)
    print("MODEL EVALUATION")
    print("="*60)

    device = torch.device(device if torch.cuda.is_available() else "cpu")
    model = model.to(device)
    model.eval()

    loader = DataLoader(dataset, batch_size=256, shuffle=False)

    correct = 0
    total = 0
    action_counts = {i: 0 for i in range(5)}

    with torch.no_grad():
        for states, labels in tqdm(loader, desc="Evaluating"):
            states = states.to(device)
            labels = labels.to(device)

            q_values = model(states)
            _, predicted = q_values.max(1)

            correct += predicted.eq(labels).sum().item()
            total += labels.size(0)

            for action in predicted.cpu().numpy():
                action_counts[action] += 1

    accuracy = 100. * correct / total

    print(f"\nAccuracy: {accuracy:.2f}%")
    print("\nAction Distribution:")
    action_names = ["MONITOR", "DEPLOY_HONEYPOT", "ISOLATE_DEVICE", "ENGAGE_ATTACKER", "ALERT_USER"]
    for i, name in enumerate(action_names):
        pct = 100. * action_counts[i] / total
        print(f"  {name}: {action_counts[i]} ({pct:.1f}%)")

    return accuracy


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Train KAAL model with CICIDS2017")
    parser.add_argument("--data_dir", type=str, default="data/cicids2017",
                        help="Directory containing CICIDS2017 CSV files")
    parser.add_argument("--epochs", type=int, default=50,
                        help="Number of supervised training epochs")
    parser.add_argument("--rl_episodes", type=int, default=10000,
                        help="Number of RL episodes")
    parser.add_argument("--batch_size", type=int, default=64,
                        help="Training batch size")
    parser.add_argument("--max_samples", type=int, default=500000,
                        help="Maximum samples to load from dataset")
    parser.add_argument("--device", type=str, default="cuda",
                        help="Device to use (cuda/cpu)")
    parser.add_argument("--skip_rl", action="store_true",
                        help="Skip RL fine-tuning (supervised only)")
    parser.add_argument("--eval_only", action="store_true",
                        help="Only evaluate existing model")
    args = parser.parse_args()

    # Create models directory
    Path("models").mkdir(exist_ok=True)

    # Check for CUDA
    if args.device == "cuda" and not torch.cuda.is_available():
        print("CUDA not available, using CPU")
        args.device = "cpu"

    print(f"Using device: {args.device}")

    # Load dataset
    print("\nLoading CICIDS2017 dataset...")
    dataset = CICIDS2017Dataset(
        data_dir=args.data_dir,
        max_samples=args.max_samples,
        balance_classes=True
    )

    # Create model
    model = DuelingDQN(state_size=10, action_size=5, hidden_size=128)

    if args.eval_only:
        # Load and evaluate existing model
        checkpoint = torch.load("models/dqn_model.pth", map_location=args.device)
        model.load_state_dict(checkpoint["policy_state_dict"])
        evaluate_model(model, dataset, args.device)
        return

    # Phase 1: Supervised pre-training
    model, accuracy = train_supervised(
        model, dataset,
        epochs=args.epochs,
        batch_size=args.batch_size,
        device=args.device
    )

    # Phase 2: RL fine-tuning
    if not args.skip_rl:
        model = train_rl(
            model, dataset,
            episodes=args.rl_episodes,
            batch_size=args.batch_size,
            device=args.device
        )

    # Final evaluation
    evaluate_model(model, dataset, args.device)

    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print("\nModel saved to: models/dqn_model.pth")
    print("\nTo use in RAKSHAK, copy the model file to your Jetson:")
    print("  scp models/dqn_model.pth jetson@<jetson-ip>:~/e-raksha/models/")


if __name__ == "__main__":
    main()
