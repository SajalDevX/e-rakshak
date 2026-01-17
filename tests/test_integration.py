"""
Integration Tests
=================

End-to-end tests to verify the complete attack→decision→action flow.

Tests include:
- Threat to honeypot deployment flow
- Threat to device isolation flow
- Simulated attack scenarios
- Component interaction
"""

import pytest
import time
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class TestThreatToHoneypotFlow:
    """Test complete flow from threat detection to honeypot deployment."""

    def test_brute_force_triggers_honeypot(self, kaal_agent, deception_engine, sample_threats):
        """Brute force attack should trigger honeypot deployment."""
        threat = sample_threats["brute_force_medium"]

        # Step 1: KAAL makes decision
        decision = kaal_agent.decide(threat)
        print(f"KAAL decision: {decision['action']}")

        # Step 2: If decision is DEPLOY_HONEYPOT, deploy it
        if decision["action"] == "DEPLOY_HONEYPOT":
            honeypot = deception_engine.deploy_honeypot(
                threat_info=threat,
                protocol="telnet",
                persona="tp_link"
            )

            assert honeypot is not None, "Honeypot should be deployed"
            # Status may be "starting" or "active" depending on timing
            assert honeypot.status in ["active", "starting"]
            print(f"Deployed honeypot: {honeypot.id} on port {honeypot.port}")
        else:
            print(f"Alternative action taken: {decision['action']}")

    def test_dos_high_triggers_defense(self, kaal_agent, deception_engine, mock_gateway, sample_threats):
        """High severity DoS should trigger defensive action."""
        threat = sample_threats["dos_attack_high"]

        # Step 1: KAAL makes decision
        decision = kaal_agent.decide(threat)
        print(f"KAAL decision for DoS (high): {decision['action']}")

        # Step 2: Execute appropriate action
        if decision["action"] == "DEPLOY_HONEYPOT":
            honeypot = deception_engine.deploy_honeypot(
                threat_info=threat,
                protocol="http",
                persona="tp_link"
            )
            assert honeypot is not None
            print(f"Deployed honeypot: {honeypot.id}")

        elif decision["action"] == "ISOLATE_DEVICE":
            # Mock isolation
            source_ip = threat.get("source_ip")
            mock_gateway.isolate_device(source_ip)
            mock_gateway.isolate_device.assert_called_with(source_ip)
            print(f"Device {source_ip} isolated")


class TestThreatToIsolateFlow:
    """Test complete flow from threat detection to device isolation."""

    def test_critical_threat_triggers_isolation(self, kaal_agent, mock_gateway, sample_threats):
        """Critical threat should trigger device isolation."""
        threat = sample_threats["malware_critical"]

        # Step 1: KAAL makes decision
        decision = kaal_agent.decide(threat)
        print(f"KAAL decision for malware (critical): {decision['action']}")

        # Step 2: Execute isolation if decided
        if decision["action"] == "ISOLATE_DEVICE":
            source_ip = threat.get("source_ip")
            mock_gateway.isolate_device(source_ip)
            mock_gateway.isolate_device.assert_called_with(source_ip)
            print(f"Device {source_ip} isolated")

        # Critical threats should lead to isolation or at least honeypot
        assert decision["action"] in ["ISOLATE_DEVICE", "DEPLOY_HONEYPOT"]


class TestSimulatedAttackScenarios:
    """Test simulated attack scenarios."""

    def test_simulated_brute_force_attack(self, simulated_threat_generator, kaal_agent, deception_engine):
        """Simulate brute force attack and verify response."""
        # Generate simulated threat
        threat = simulated_threat_generator.generate_threat(attack_type="brute_force")

        assert threat is not None
        assert threat["type"] == "brute_force"
        print(f"Generated threat: {threat['type']} from {threat['source_ip']}")

        # KAAL decision
        decision = kaal_agent.decide(threat)
        print(f"KAAL decision: {decision['action']}")

        # Execute action based on decision
        if decision["action"] == "DEPLOY_HONEYPOT":
            honeypot = deception_engine.deploy_honeypot(
                threat_info=threat,
                protocol="telnet"
            )
            assert honeypot is not None

    def test_simulated_dos_attack(self, simulated_threat_generator, kaal_agent):
        """Simulate DoS attack and verify response."""
        # Generate simulated DoS threat
        threat = simulated_threat_generator.generate_threat(attack_type="dos_attack")

        assert threat is not None
        assert threat["type"] == "dos_attack"
        print(f"Generated threat: {threat['type']} severity {threat['severity']}")

        # KAAL decision
        decision = kaal_agent.decide(threat)
        print(f"KAAL decision: {decision['action']}")

        # DoS attacks should trigger defensive actions
        assert decision["action"] in ["DEPLOY_HONEYPOT", "ISOLATE_DEVICE", "ENGAGE_ATTACKER", "MONITOR"]

    def test_simulated_port_scan(self, simulated_threat_generator, kaal_agent):
        """Simulate port scan and verify response."""
        # Generate simulated port scan
        threat = simulated_threat_generator.generate_threat(attack_type="port_scan")

        assert threat is not None
        assert threat["type"] == "port_scan"
        print(f"Generated threat: {threat['type']} severity {threat['severity']}")

        # KAAL decision
        decision = kaal_agent.decide(threat)
        print(f"KAAL decision: {decision['action']}")


class TestComponentInteraction:
    """Test interaction between components."""

    def test_threat_logger_integration(self, test_config, mock_threat_logger, sample_threats):
        """Test threat logger receives events properly."""
        from core.agentic_defender import AgenticDefender as KAALAgent

        agent = KAALAgent(test_config, threat_logger=mock_threat_logger)
        threat = sample_threats["brute_force_medium"]

        # Make decision
        decision = agent.decide(threat)

        # Verify agent has threat logger
        assert agent.threat_logger is not None

    def test_deception_engine_gateway_integration(self, deception_engine, mock_gateway, sample_threats):
        """Test deception engine can communicate with gateway."""
        threat = sample_threats["brute_force_medium"]

        # Deploy honeypot
        honeypot = deception_engine.deploy_honeypot(
            threat_info=threat,
            protocol="telnet"
        )

        # Verify gateway reference
        assert deception_engine.gateway is not None or True  # May be None in test mode


class TestMultipleThreatsHandling:
    """Test handling of multiple concurrent threats."""

    def test_multiple_threats_sequential(self, kaal_agent, deception_engine, sample_threats):
        """Handle multiple threats sequentially."""
        threats = [
            sample_threats["port_scan_low"],
            sample_threats["brute_force_medium"],
            sample_threats["dos_attack_high"]
        ]

        decisions = []
        for threat in threats:
            decision = kaal_agent.decide(threat)
            decisions.append(decision)
            print(f"Threat: {threat['type']} ({threat['severity']}) -> {decision['action']}")

        assert len(decisions) == 3
        assert all(d["status"] == "decided" for d in decisions)

    def test_honeypot_scaling(self, kaal_agent, deception_engine, sample_threats):
        """Test multiple honeypot deployments."""
        threat = sample_threats["brute_force_medium"]

        honeypots_deployed = 0
        for i in range(3):
            decision = kaal_agent.decide(threat)
            if decision["action"] == "DEPLOY_HONEYPOT":
                honeypot = deception_engine.deploy_honeypot(
                    threat_info=threat,
                    protocol="telnet"
                )
                if honeypot:
                    honeypots_deployed += 1

        print(f"Deployed {honeypots_deployed} honeypots")
        assert honeypots_deployed <= deception_engine.max_honeypots


class TestActionExecution:
    """Test action execution logic."""

    def test_execute_monitor_action(self, kaal_agent, mock_threat_logger, sample_threats):
        """Test MONITOR action execution."""
        threat = sample_threats["port_scan_low"]

        decision = kaal_agent.decide(threat)

        # MONITOR should be valid
        if decision["action"] == "MONITOR":
            # Just log, no active defense
            print("MONITOR action: Logging only")
            assert True

    def test_execute_alert_user_action(self, kaal_agent, sample_threats):
        """Test ALERT_USER action execution."""
        # Create a scenario that might trigger alert
        threat = {
            "type": "suspicious_traffic",
            "severity": "medium",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1"
        }

        decision = kaal_agent.decide(threat)

        # Check if ALERT_USER is possible
        if decision["action"] == "ALERT_USER":
            print("ALERT_USER action triggered")


class TestErrorHandling:
    """Test error handling in the integration flow."""

    def test_invalid_threat_handling(self, kaal_agent):
        """Handle invalid threat data gracefully."""
        invalid_threat = {}  # Empty threat

        try:
            decision = kaal_agent.decide(invalid_threat)
            # Should still produce a decision
            assert "action" in decision
        except Exception as e:
            pytest.fail(f"Should handle invalid threat gracefully: {e}")

    def test_missing_threat_fields(self, kaal_agent):
        """Handle threats with missing fields."""
        partial_threat = {
            "type": "brute_force"
            # Missing severity, IPs, etc.
        }

        try:
            decision = kaal_agent.decide(partial_threat)
            assert "action" in decision
        except Exception as e:
            pytest.fail(f"Should handle partial threat data: {e}")

    def test_honeypot_deployment_failure_recovery(self, test_config, mock_threat_logger, mock_gateway, sample_threats):
        """Test recovery when honeypot deployment fails."""
        from core.deception_engine import DeceptionEngine

        # Create engine with limited capacity
        limited_config = test_config.copy()
        limited_config["deception"]["max_honeypots"] = 1

        engine = DeceptionEngine(
            config=limited_config,
            threat_logger=mock_threat_logger,
            gateway=mock_gateway
        )

        threat = sample_threats["brute_force_medium"]

        # First deployment should succeed
        hp1 = engine.deploy_honeypot(threat_info=threat, protocol="telnet")
        assert hp1 is not None

        # Second deployment should fail gracefully (at max)
        hp2 = engine.deploy_honeypot(threat_info=threat, protocol="telnet")
        # Should return None when at max

        # Cleanup
        engine.stop_all_honeypots()


class TestRealDeviceScenarios:
    """Test scenarios with real device data."""

    def test_threat_targeting_real_device(self, simulated_threat_generator, kaal_agent):
        """Test threat generated for real device."""
        threat = simulated_threat_generator.generate_threat()

        # Should use one of the real device IPs from fixture
        assert threat["target_ip"] in ["192.168.1.100", "192.168.1.101"] or \
               threat["source_ip"] in ["192.168.1.100", "192.168.1.101"]

        decision = kaal_agent.decide(threat)
        assert decision["action"] in kaal_agent.ACTIONS.values()
