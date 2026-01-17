"""
RAKSHAK Test Fixtures
=====================

Shared pytest fixtures for testing KAAL agent, honeypot deployment,
LLM honeypot responses, and integration tests.
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def test_config():
    """Basic test configuration."""
    return {
        "general": {
            "app_name": "RAKSHAK",
            "version": "1.0.0",
            "debug": True,
            "language": "en"
        },
        "simulation": {
            "enabled": True,
            "num_fake_devices": 5
        },
        "agent": {
            "model_path": "models/kaal_policy.pth",
            "state_size": 10,
            "action_size": 5,
            "learning_rate": 0.001,
            "gamma": 0.99,
            "epsilon_start": 0.0,  # No exploration for deterministic tests
            "epsilon_end": 0.01,
            "epsilon_decay": 0.995,
            "hidden_layers": [128, 128],
            "severity_thresholds": {
                "low": 30,
                "medium": 60,
                "high": 80,
                "critical": 95
            }
        },
        "kaal": {
            "inference_only": True,
            "model_path": "models/kaal_policy.pth",
            "event_publishing": {
                "enabled": False  # Disable for tests
            }
        },
        "deception": {
            "enabled": True,
            "max_honeypots": 5,
            "honeypot_ports": {
                "telnet": 12323,  # Use high ports for tests
                "ssh": 12222,
                "http": 18080,
                "mqtt": 11883
            }
        },
        "llm": {
            "ollama_enabled": False,  # Disable for tests
            "personas": {
                "tp_link": {
                    "name": "TP-Link Archer C7",
                    "firmware": "3.15.3",
                    "os": "Linux 2.6.36",
                    "banner": "TP-Link HTTP Server"
                },
                "wyze_cam": {
                    "name": "Wyze Cam v2",
                    "firmware": "4.9.8.1002",
                    "os": "Linux 3.4.35",
                    "banner": "Wyze Camera v2 - RTSP Server"
                }
            }
        },
        "gateway": {
            "enabled": False,  # Disable for tests
            "wan_interface": "eth0",
            "lan_interface": "eth1"
        }
    }


@pytest.fixture
def mock_threat_logger():
    """Mock threat logger."""
    logger = Mock()
    logger.log_threat = Mock(return_value=Mock(
        id="threat-001",
        to_dict=Mock(return_value={
            "id": "threat-001",
            "type": "brute_force",
            "severity": "medium",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "timestamp": datetime.now().isoformat()
        })
    ))
    logger.log_action = Mock()
    logger.get_recent_threats = Mock(return_value=[])
    logger.get_recent_actions = Mock(return_value=[])
    logger.add_to_queue = Mock()
    return logger


@pytest.fixture
def mock_gateway():
    """Mock gateway for testing."""
    gateway = Mock()
    gateway.is_gateway_mode = False
    gateway.isolated_devices = {}
    gateway.isolate_device = Mock(return_value=True)
    gateway.release_device = Mock(return_value=True)
    gateway.redirect_to_honeypot = Mock(return_value=True)
    gateway.remove_honeypot_redirect = Mock(return_value=True)
    return gateway


@pytest.fixture
def sample_threats():
    """Sample threat data for various attack types and severities."""
    return {
        "port_scan_low": {
            "id": "threat-ps-001",
            "type": "port_scan",
            "severity": "low",
            "source_ip": "192.168.1.100",
            "target_ip": "192.168.1.1",
            "target_device": "Router",
            "source_port": 45000,
            "target_port": 22,
            "protocol": "tcp",
            "packets_count": 10,
            "duration_seconds": 5
        },
        "brute_force_medium": {
            "id": "threat-bf-001",
            "type": "brute_force",
            "severity": "medium",
            "source_ip": "192.168.1.101",
            "target_ip": "192.168.1.1",
            "target_device": "Router",
            "source_port": 46000,
            "target_port": 23,
            "protocol": "tcp",
            "packets_count": 100,
            "duration_seconds": 30
        },
        "dos_attack_high": {
            "id": "threat-dos-001",
            "type": "dos_attack",
            "severity": "high",
            "source_ip": "192.168.1.102",
            "target_ip": "192.168.1.50",
            "target_device": "IP Camera",
            "source_port": 0,
            "target_port": 80,
            "protocol": "tcp",
            "packets_count": 10000,
            "duration_seconds": 60
        },
        "dos_attack_critical": {
            "id": "threat-dos-002",
            "type": "dos_attack",
            "severity": "critical",
            "source_ip": "192.168.1.103",
            "target_ip": "192.168.1.50",
            "target_device": "IP Camera",
            "source_port": 0,
            "target_port": 80,
            "protocol": "tcp",
            "packets_count": 50000,
            "duration_seconds": 120
        },
        "exploit_attempt_high": {
            "id": "threat-exp-001",
            "type": "exploit_attempt",
            "severity": "high",
            "source_ip": "192.168.1.104",
            "target_ip": "192.168.1.1",
            "target_device": "Router",
            "source_port": 47000,
            "target_port": 80,
            "protocol": "tcp",
            "packets_count": 50,
            "duration_seconds": 10
        },
        "malware_critical": {
            "id": "threat-mal-001",
            "type": "malware",
            "severity": "critical",
            "source_ip": "192.168.1.105",
            "target_ip": "192.168.1.60",
            "target_device": "Smart TV",
            "source_port": 0,
            "target_port": 443,
            "protocol": "tcp",
            "packets_count": 200,
            "duration_seconds": 15
        }
    }


@pytest.fixture
def kaal_agent(test_config, mock_threat_logger):
    """Create KAAL agent for testing."""
    from core.agentic_defender import AgenticDefender as KAALAgent
    agent = KAALAgent(test_config, threat_logger=mock_threat_logger)
    return agent


@pytest.fixture
def deception_engine(test_config, mock_threat_logger, mock_gateway):
    """Create deception engine for testing."""
    from core.deception_engine import DeceptionEngine
    engine = DeceptionEngine(
        config=test_config,
        llm_honeypot=None,  # No LLM for basic tests
        threat_logger=mock_threat_logger,
        gateway=mock_gateway
    )
    yield engine
    # Cleanup: stop all honeypots after test
    engine.stop_all_honeypots()


@pytest.fixture
def mock_llm_honeypot():
    """Mock LLM honeypot for testing."""
    llm = Mock()

    # Static responses for common commands
    static_responses = {
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "whoami": "root",
        "uname -a": "Linux router 2.6.36 #1 SMP PREEMPT armv7l GNU/Linux",
        "id": "uid=0(root) gid=0(root) groups=0(root)",
        "ls -la": "total 24\ndrwxr-xr-x  4 root root 4096 Jan 15 10:00 .\ndrwxr-xr-x  4 root root 4096 Jan 15 10:00 ..",
        "pwd": "/root"
    }

    def generate_response(command, persona=None, session_context=None):
        cmd_lower = command.lower().strip()
        for pattern, response in static_responses.items():
            if pattern in cmd_lower:
                return response
        return f"sh: {command}: command not found"

    llm.generate_response = Mock(side_effect=generate_response)
    llm.get_banner = Mock(return_value="TP-Link Wireless Router WR940N\nLogin: ")
    llm.validate_credentials = Mock(return_value=False)
    llm.capture_credentials = Mock()

    return llm


@pytest.fixture
def network_scanner(test_config, mock_gateway):
    """Create network scanner for testing."""
    from core.network_scanner import NetworkScanner
    scanner = NetworkScanner(config=test_config, gateway=mock_gateway)
    return scanner


@pytest.fixture
def simulated_threat_generator(test_config):
    """Create simulated threat generator."""
    from core.threat_logger import SimulatedThreatGenerator

    real_devices = [
        {"ip": "192.168.1.100", "hostname": "test-device-1", "name": "Test Device 1"},
        {"ip": "192.168.1.101", "hostname": "test-device-2", "name": "Test Device 2"},
    ]

    return SimulatedThreatGenerator(test_config, real_devices=real_devices)
