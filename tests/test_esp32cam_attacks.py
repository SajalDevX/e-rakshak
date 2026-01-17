#!/usr/bin/env python3
"""
ESP32-CAM Attack Testing Script
================================

Simulates various attacks against a vulnerable ESP32-CAM to test e-raksha's
detection and response capabilities.

Target: ESP32-CAM at 10.42.0.103
Tests:
1. Port scanning
2. HTTP enumeration
3. Repeated unauthorized access
4. Potential lateral movement simulation

Author: Team RAKSHAK
"""

import time
import socket
import requests
from typing import List, Dict
from loguru import logger

# ================== CONFIGURATION ==================
TARGET_IP = "10.42.0.103"
TARGET_NAME = "ESP32-CAM"
GATEWAY_IP = "10.42.0.1"
DASHBOARD_URL = f"http://{GATEWAY_IP}:5000"
# ===================================================


class ESP32CamAttackSimulator:
    """Simulates attacks against ESP32-CAM for testing e-raksha detection."""

    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.results = []

    def test_port_scan(self, ports: List[int] = None) -> Dict:
        """
        Test 1: Port Scanning

        Expected Detection:
        - Port scan detector should detect SYN scan pattern
        - Risk score should increase
        - Response: RATE_LIMIT or DEPLOY_HONEYPOT
        """
        if ports is None:
            ports = [21, 22, 23, 80, 443, 554, 8080, 8081, 8888, 9000]

        logger.info(f"[TEST 1] Port scanning {self.target_ip}...")
        open_ports = []
        start_time = time.time()

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target_ip, port))

                if result == 0:
                    open_ports.append(port)
                    logger.success(f"  Port {port}/tcp OPEN")
                else:
                    logger.debug(f"  Port {port}/tcp CLOSED")

                sock.close()
                time.sleep(0.1)  # Rapid scanning to trigger detection
            except Exception as e:
                logger.error(f"  Port {port} error: {e}")

        duration = time.time() - start_time

        result = {
            "test": "port_scan",
            "target": self.target_ip,
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "duration": duration,
            "expected_detection": "port_scan_detector",
            "expected_response": "RATE_LIMIT or DEPLOY_HONEYPOT",
            "severity": "MEDIUM"
        }

        self.results.append(result)
        logger.info(f"  Found {len(open_ports)} open ports in {duration:.2f}s")
        logger.warning("  Expected: e-raksha should detect SYN scan pattern")
        return result

    def test_http_enumeration(self) -> Dict:
        """
        Test 2: HTTP Enumeration

        Expected Detection:
        - High request rate to vulnerable service
        - Device type: camera (high risk)
        - Response: DEPLOY_HONEYPOT
        """
        logger.info(f"[TEST 2] HTTP enumeration on {self.target_ip}...")

        paths = [
            "/",
            "/stream",
            "/admin",
            "/config",
            "/cgi-bin",
            "/api/v1",
            "/camera",
            "/snapshot"
        ]

        results = {"found": [], "not_found": []}
        start_time = time.time()

        for path in paths:
            try:
                url = f"http://{self.target_ip}{path}"
                response = requests.get(url, timeout=2)

                if response.status_code == 200:
                    results["found"].append(path)
                    logger.success(f"  Found: {path} (200 OK)")
                else:
                    results["not_found"].append(path)
                    logger.debug(f"  Not found: {path} ({response.status_code})")

                time.sleep(0.1)  # Rapid requests to trigger detection
            except requests.exceptions.ConnectionError:
                logger.error(f"  Connection refused: {path}")
                results["not_found"].append(path)
            except Exception as e:
                logger.error(f"  Error on {path}: {e}")
                results["not_found"].append(path)

        duration = time.time() - start_time

        result = {
            "test": "http_enumeration",
            "target": self.target_ip,
            "paths_tested": len(paths),
            "found": results["found"],
            "duration": duration,
            "expected_detection": "high_request_rate + camera_device_type",
            "expected_response": "DEPLOY_HONEYPOT",
            "severity": "MEDIUM"
        }

        self.results.append(result)
        logger.info(f"  Found {len(results['found'])} endpoints in {duration:.2f}s")
        logger.warning("  Expected: e-raksha should detect enumeration pattern")
        return result

    def test_unauthorized_stream_access(self, count: int = 10) -> Dict:
        """
        Test 3: Repeated Unauthorized Stream Access

        Expected Detection:
        - Repeat offender pattern
        - Vulnerability: No authentication
        - Response: QUARANTINE (escalated from RATE_LIMIT)
        """
        logger.info(f"[TEST 3] Repeated stream access ({count} requests)...")

        success_count = 0
        start_time = time.time()

        for i in range(count):
            try:
                url = f"http://{self.target_ip}/stream"
                response = requests.get(url, timeout=1, stream=True)

                if response.status_code == 200:
                    # Read a small chunk to simulate viewing
                    chunk = next(response.iter_content(chunk_size=1024), None)
                    if chunk:
                        success_count += 1
                        logger.debug(f"  Request {i+1}/{count}: SUCCESS (streaming)")

                response.close()
                time.sleep(0.2)  # Rapid repeated access
            except Exception as e:
                logger.error(f"  Request {i+1} failed: {e}")

        duration = time.time() - start_time

        result = {
            "test": "unauthorized_stream_access",
            "target": self.target_ip,
            "requests": count,
            "successful": success_count,
            "duration": duration,
            "expected_detection": "repeat_offender + no_authentication",
            "expected_response": "QUARANTINE (escalated)",
            "severity": "HIGH"
        }

        self.results.append(result)
        logger.info(f"  {success_count}/{count} successful unauthorized accesses in {duration:.2f}s")
        logger.warning("  Expected: e-raksha should escalate response level")
        return result

    def test_vulnerability_exploit_simulation(self) -> Dict:
        """
        Test 4: Simulated Exploit Attempt

        Expected Detection:
        - Malicious payload pattern
        - Command injection attempt
        - Response: ISOLATE
        """
        logger.info(f"[TEST 4] Simulating exploit attempts...")

        # Simulated command injection payloads (harmless - just testing detection)
        payloads = [
            "/stream?cmd=;cat /etc/passwd",
            "/stream?debug=`whoami`",
            "/admin?user=admin' OR '1'='1",
            "/config?ssid=$(reboot)",
        ]

        exploit_attempts = []
        start_time = time.time()

        for payload in payloads:
            try:
                url = f"http://{self.target_ip}{payload}"
                response = requests.get(url, timeout=2)

                exploit_attempts.append({
                    "payload": payload,
                    "status": response.status_code,
                    "detected": "Unknown"  # Would need IDS integration
                })

                logger.debug(f"  Payload sent: {payload[:50]}...")
                time.sleep(0.5)
            except Exception as e:
                logger.error(f"  Exploit attempt failed: {e}")

        duration = time.time() - start_time

        result = {
            "test": "exploit_simulation",
            "target": self.target_ip,
            "payloads": len(payloads),
            "attempts": exploit_attempts,
            "duration": duration,
            "expected_detection": "ids_classifier + malicious_pattern",
            "expected_response": "ISOLATE",
            "severity": "CRITICAL"
        }

        self.results.append(result)
        logger.info(f"  Sent {len(payloads)} simulated exploit payloads in {duration:.2f}s")
        logger.warning("  Expected: e-raksha should detect malicious patterns and isolate device")
        return result

    def check_isolation_status(self) -> Dict:
        """
        Check if device was isolated by e-raksha.

        Tries to:
        1. Connect to ESP32-CAM (should fail if isolated)
        2. Query dashboard for device status
        """
        logger.info(f"[VERIFICATION] Checking isolation status...")

        # Test 1: Try to connect to camera
        can_connect = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target_ip, 80))
            can_connect = (result == 0)
            sock.close()
        except:
            can_connect = False

        # Test 2: Check dashboard status
        dashboard_status = None
        try:
            response = requests.get(f"{DASHBOARD_URL}/api/devices", timeout=5)
            if response.status_code == 200:
                devices = response.json()
                for device in devices:
                    if device.get("ip") == self.target_ip:
                        dashboard_status = device.get("status")
                        break
        except Exception as e:
            logger.warning(f"  Could not query dashboard: {e}")

        result = {
            "target": self.target_ip,
            "can_connect": can_connect,
            "dashboard_status": dashboard_status,
            "is_isolated": not can_connect or dashboard_status == "isolated"
        }

        if result["is_isolated"]:
            logger.success(f"  VERIFIED: Device is ISOLATED by e-raksha")
        else:
            logger.warning(f"  WARNING: Device is NOT isolated (can_connect={can_connect})")

        return result

    def print_summary(self):
        """Print test summary and expected e-raksha responses."""
        logger.info("\n" + "="*60)
        logger.info("TEST SUMMARY")
        logger.info("="*60)

        for i, result in enumerate(self.results, 1):
            logger.info(f"\n[Test {i}] {result['test'].upper()}")
            logger.info(f"  Severity: {result.get('severity', 'N/A')}")
            logger.info(f"  Expected Detection: {result.get('expected_detection', 'N/A')}")
            logger.info(f"  Expected Response: {result.get('expected_response', 'N/A')}")

        logger.info("\n" + "="*60)
        logger.info("WHAT E-RAKSHA SHOULD DO:")
        logger.info("="*60)
        logger.info("1. Port Scan Detection:")
        logger.info("   - Detect SYN scan pattern (10 ports in <5s)")
        logger.info("   - Response: RATE_LIMIT (Level 2)")
        logger.info("")
        logger.info("2. HTTP Enumeration Detection:")
        logger.info("   - Detect high request rate to vulnerable HTTP service")
        logger.info("   - Identify device as 'camera' (high risk)")
        logger.info("   - Response: DEPLOY_HONEYPOT (Level 3)")
        logger.info("")
        logger.info("3. Repeat Offender Escalation:")
        logger.info("   - Detect multiple unauthorized access attempts")
        logger.info("   - Escalate response level for repeat offender")
        logger.info("   - Response: QUARANTINE (Level 4)")
        logger.info("")
        logger.info("4. Exploit Attempt Detection:")
        logger.info("   - IDS detects malicious payload patterns")
        logger.info("   - High confidence of compromise")
        logger.info("   - Response: ISOLATE (Level 5) or FULL_BLOCK (Level 6)")
        logger.info("")
        logger.info("5. Final State:")
        logger.info("   - Device 10.42.0.103 should be ISOLATED")
        logger.info("   - Dashboard should show status='isolated'")
        logger.info("   - All traffic from device blocked by iptables")
        logger.info("="*60)


def main():
    """Run comprehensive attack simulation."""
    logger.info("="*60)
    logger.info("ESP32-CAM ATTACK SIMULATION - Testing e-raksha Detection")
    logger.info("="*60)
    logger.info(f"Target: {TARGET_NAME} ({TARGET_IP})")
    logger.info(f"Gateway: {GATEWAY_IP}")
    logger.info("="*60)
    logger.info("")

    simulator = ESP32CamAttackSimulator(TARGET_IP)

    # Give user time to prepare
    logger.info("Starting attack simulation in 5 seconds...")
    logger.info("Monitor e-raksha dashboard at http://10.42.0.1:5000")
    time.sleep(5)

    try:
        # Test 1: Port Scanning
        logger.info("\n" + "-"*60)
        simulator.test_port_scan()
        logger.info("Waiting 10s for e-raksha to process...")
        time.sleep(10)

        # Test 2: HTTP Enumeration
        logger.info("\n" + "-"*60)
        simulator.test_http_enumeration()
        logger.info("Waiting 10s for e-raksha to process...")
        time.sleep(10)

        # Test 3: Repeated Unauthorized Access
        logger.info("\n" + "-"*60)
        simulator.test_unauthorized_stream_access(count=15)
        logger.info("Waiting 10s for e-raksha to process...")
        time.sleep(10)

        # Test 4: Exploit Simulation
        logger.info("\n" + "-"*60)
        simulator.test_vulnerability_exploit_simulation()
        logger.info("Waiting 15s for e-raksha to process and isolate...")
        time.sleep(15)

        # Verification
        logger.info("\n" + "-"*60)
        isolation_status = simulator.check_isolation_status()

        # Print summary
        simulator.print_summary()

        # Final recommendation
        logger.info("\nNEXT STEPS:")
        logger.info("1. Check e-raksha dashboard for threats detected")
        logger.info("2. Verify device 10.42.0.103 is marked as 'isolated'")
        logger.info("3. Check threat_logger.db for recorded events")
        logger.info("4. Review KAAL agent's decisions in the logs")

        if isolation_status["is_isolated"]:
            logger.success("\n✓ SUCCESS: e-raksha successfully isolated the vulnerable camera!")
        else:
            logger.error("\n✗ FAILED: Device was not isolated. Check e-raksha logs.")

    except KeyboardInterrupt:
        logger.warning("\nTest interrupted by user")
    except Exception as e:
        logger.error(f"\nTest failed: {e}")

if __name__ == "__main__":
    main()
