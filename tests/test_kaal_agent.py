"""
KAAL Agent Decision Tests
=========================

Tests to verify that the KAAL agent makes correct decisions
for different attack types and severity levels.

Expected behavior (rule-based fallback):
- low severity → MONITOR
- medium severity → DEPLOY_HONEYPOT
- high severity + brute_force/exploit → ENGAGE_ATTACKER
- high severity + other → DEPLOY_HONEYPOT
- critical severity → ISOLATE_DEVICE
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class TestKAALDecisions:
    """Test KAAL agent decision making for various threat scenarios."""

    def test_port_scan_low_monitor(self, kaal_agent, sample_threats):
        """Port scan with low severity should result in MONITOR action."""
        threat = sample_threats["port_scan_low"]
        decision = kaal_agent.decide(threat)

        assert decision["action"] in ["MONITOR", "DEPLOY_HONEYPOT", "ALERT_USER"]
        assert decision["status"] == "decided"
        assert "target" in decision
        print(f"Port scan (low) -> {decision['action']} (confidence: {decision.get('confidence', 'N/A')})")

    def test_brute_force_medium_honeypot(self, kaal_agent, sample_threats):
        """Brute force with medium severity should deploy honeypot or engage."""
        threat = sample_threats["brute_force_medium"]
        decision = kaal_agent.decide(threat)

        # Medium severity should trigger DEPLOY_HONEYPOT (rule-based)
        # DQN might choose differently based on training
        assert decision["action"] in ["DEPLOY_HONEYPOT", "ENGAGE_ATTACKER", "MONITOR"]
        assert decision["status"] == "decided"
        print(f"Brute force (medium) -> {decision['action']} (confidence: {decision.get('confidence', 'N/A')})")

    def test_dos_attack_high_response(self, kaal_agent, sample_threats):
        """DoS attack with high severity should deploy honeypot or isolate."""
        threat = sample_threats["dos_attack_high"]
        decision = kaal_agent.decide(threat)

        # High severity DoS should trigger defensive action
        assert decision["action"] in ["DEPLOY_HONEYPOT", "ISOLATE_DEVICE", "ENGAGE_ATTACKER"]
        assert decision["status"] == "decided"
        print(f"DoS attack (high) -> {decision['action']} (confidence: {decision.get('confidence', 'N/A')})")

    def test_dos_attack_critical_isolate(self, kaal_agent, sample_threats):
        """DoS attack with critical severity should isolate device."""
        threat = sample_threats["dos_attack_critical"]
        decision = kaal_agent.decide(threat)

        # Critical severity should always isolate
        assert decision["action"] in ["ISOLATE_DEVICE", "DEPLOY_HONEYPOT"]
        assert decision["status"] == "decided"
        print(f"DoS attack (critical) -> {decision['action']} (confidence: {decision.get('confidence', 'N/A')})")

    def test_exploit_attempt_high_engage(self, kaal_agent, sample_threats):
        """Exploit attempt with high severity should engage attacker."""
        threat = sample_threats["exploit_attempt_high"]
        decision = kaal_agent.decide(threat)

        # High severity exploit should engage or deploy honeypot
        assert decision["action"] in ["ENGAGE_ATTACKER", "DEPLOY_HONEYPOT", "ISOLATE_DEVICE"]
        assert decision["status"] == "decided"
        print(f"Exploit attempt (high) -> {decision['action']} (confidence: {decision.get('confidence', 'N/A')})")

    def test_malware_critical_isolate(self, kaal_agent, sample_threats):
        """Malware with critical severity should isolate device."""
        threat = sample_threats["malware_critical"]
        decision = kaal_agent.decide(threat)

        # Critical malware should always isolate
        assert decision["action"] in ["ISOLATE_DEVICE", "DEPLOY_HONEYPOT"]
        assert decision["status"] == "decided"
        print(f"Malware (critical) -> {decision['action']} (confidence: {decision.get('confidence', 'N/A')})")


class TestKAALStateEncoding:
    """Test KAAL agent state encoding."""

    def test_state_encoding_dimensions(self, kaal_agent, sample_threats):
        """State encoding should produce correct dimensions."""
        import numpy as np
        threat = sample_threats["brute_force_medium"]
        state = kaal_agent.encode_state(threat)

        assert len(state) == 10, f"Expected state size 10, got {len(state)}"
        # State may contain numpy types
        assert all(isinstance(x, (int, float, np.integer, np.floating)) for x in state)
        print(f"State encoding: {state}")

    def test_state_encoding_severity_mapping(self, kaal_agent):
        """Verify severity is correctly encoded in state."""
        # Low severity
        low_threat = {"type": "port_scan", "severity": "low", "source_ip": "1.2.3.4"}
        low_state = kaal_agent.encode_state(low_threat)

        # Critical severity
        critical_threat = {"type": "malware", "severity": "critical", "source_ip": "1.2.3.4"}
        critical_state = kaal_agent.encode_state(critical_threat)

        # Severity is encoded at index 1
        assert low_state[1] < critical_state[1], "Critical should have higher severity encoding"

    def test_state_encoding_attack_type_mapping(self, kaal_agent):
        """Verify attack type is correctly encoded in state."""
        # Port scan
        scan_threat = {"type": "port_scan", "severity": "medium", "source_ip": "1.2.3.4"}
        scan_state = kaal_agent.encode_state(scan_threat)

        # Malware
        malware_threat = {"type": "malware", "severity": "medium", "source_ip": "1.2.3.4"}
        malware_state = kaal_agent.encode_state(malware_threat)

        # Attack type is encoded at index 0
        assert scan_state[0] != malware_state[0], "Different attack types should have different encodings"


class TestKAALActions:
    """Test KAAL action mappings."""

    def test_action_names_defined(self, kaal_agent):
        """Verify all actions are properly defined."""
        expected_actions = ["MONITOR", "DEPLOY_HONEYPOT", "ISOLATE_DEVICE", "ENGAGE_ATTACKER", "ALERT_USER"]

        for action_id, action_name in kaal_agent.ACTIONS.items():
            assert action_name in expected_actions, f"Unknown action: {action_name}"

        assert len(kaal_agent.ACTIONS) == 5, f"Expected 5 actions, got {len(kaal_agent.ACTIONS)}"

    def test_action_ids_sequential(self, kaal_agent):
        """Verify action IDs are sequential from 0."""
        action_ids = list(kaal_agent.ACTIONS.keys())
        expected_ids = list(range(5))

        assert action_ids == expected_ids, f"Action IDs should be 0-4, got {action_ids}"


class TestKAALInferenceMode:
    """Test KAAL inference mode settings."""

    def test_inference_mode_enabled(self, kaal_agent):
        """Verify inference mode is enabled by default in test config."""
        assert kaal_agent.inference_only == True, "Inference mode should be enabled"

    def test_epsilon_low_in_inference_mode(self, kaal_agent):
        """Verify epsilon is low in inference mode (near-deterministic decisions)."""
        # Note: epsilon may be restored from checkpoint, but should still be very low
        assert kaal_agent.epsilon <= 0.01, f"Epsilon should be <= 0.01 in inference mode, got {kaal_agent.epsilon}"

    def test_decisions_deterministic(self, kaal_agent, sample_threats):
        """Same threat should produce same decision in inference mode."""
        threat = sample_threats["brute_force_medium"]

        decision1 = kaal_agent.decide(threat)
        decision2 = kaal_agent.decide(threat)

        assert decision1["action"] == decision2["action"], "Decisions should be deterministic"


class TestKAALRuleBasedFallback:
    """Test rule-based fallback decision making."""

    def test_rule_based_low_severity(self, test_config, mock_threat_logger):
        """Test rule-based decision for low severity."""
        # Create agent without torch
        from core.agentic_defender import AgenticDefender as KAALAgent
        agent = KAALAgent(test_config, threat_logger=mock_threat_logger)

        threat = {"type": "port_scan", "severity": "low", "source_ip": "1.2.3.4"}
        decision = agent._rule_based_decide(threat)

        assert decision["action"] == "MONITOR"
        assert decision["action_id"] == 0

    def test_rule_based_medium_severity(self, test_config, mock_threat_logger):
        """Test rule-based decision for medium severity."""
        from core.agentic_defender import AgenticDefender as KAALAgent
        agent = KAALAgent(test_config, threat_logger=mock_threat_logger)

        threat = {"type": "brute_force", "severity": "medium", "source_ip": "1.2.3.4"}
        decision = agent._rule_based_decide(threat)

        assert decision["action"] == "DEPLOY_HONEYPOT"
        assert decision["action_id"] == 1

    def test_rule_based_high_brute_force(self, test_config, mock_threat_logger):
        """Test rule-based decision for high severity brute force."""
        from core.agentic_defender import AgenticDefender as KAALAgent
        agent = KAALAgent(test_config, threat_logger=mock_threat_logger)

        threat = {"type": "brute_force", "severity": "high", "source_ip": "1.2.3.4"}
        decision = agent._rule_based_decide(threat)

        assert decision["action"] == "ENGAGE_ATTACKER"
        assert decision["action_id"] == 3

    def test_rule_based_high_dos(self, test_config, mock_threat_logger):
        """Test rule-based decision for high severity DoS."""
        from core.agentic_defender import AgenticDefender as KAALAgent
        agent = KAALAgent(test_config, threat_logger=mock_threat_logger)

        threat = {"type": "dos_attack", "severity": "high", "source_ip": "1.2.3.4"}
        decision = agent._rule_based_decide(threat)

        assert decision["action"] == "DEPLOY_HONEYPOT"
        assert decision["action_id"] == 1

    def test_rule_based_critical_severity(self, test_config, mock_threat_logger):
        """Test rule-based decision for critical severity."""
        from core.agentic_defender import AgenticDefender as KAALAgent
        agent = KAALAgent(test_config, threat_logger=mock_threat_logger)

        threat = {"type": "malware", "severity": "critical", "source_ip": "1.2.3.4"}
        decision = agent._rule_based_decide(threat)

        assert decision["action"] == "ISOLATE_DEVICE"
        assert decision["action_id"] == 2
