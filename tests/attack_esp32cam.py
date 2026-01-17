#!/usr/bin/env python3
"""
ESP32-CAM Attack Simulation Script
===================================

Simulates real-world attacks against an ESP32-CAM device to test
RAKSHAK's threat detection and automatic isolation capabilities.

Target: ESP32-CAM (MAC: 94:B9:7E:FA:E3:58, IP: 10.42.0.103)

Attack Patterns:
1. Port scanning (nmap)
2. Aggressive service enumeration
3. Repeated unauthorized HTTP access
4. Banner grabbing
5. Vulnerability scanning

Expected RAKSHAK Response:
- Detect port scan via PortScanDetector
- AI agents identify suspicious behavior
- Automatic device isolation
- Alert generation

Author: Team RAKSHAK
"""

import argparse
import os
import subprocess
import sys
import time
import requests
import socket
from datetime import datetime
from typing import List, Dict
import threading

# ANSI colors for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Print attack simulation banner."""
    banner = f"""
{Colors.HEADER}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║                   ESP32-CAM ATTACK SIMULATION                            ║
║                   Testing RAKSHAK Detection                              ║
╚══════════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.OKCYAN}Target Device:{Colors.ENDC}  ESP32-CAM (Espressif)
{Colors.OKCYAN}MAC Address:{Colors.ENDC}   94:B9:7E:FA:E3:58
{Colors.OKCYAN}IP Address:{Colors.ENDC}    10.42.0.103
{Colors.OKCYAN}Service:{Colors.ENDC}       HTTP Camera Stream (Port 80)
{Colors.WARNING}
⚠️  This is a controlled security test on authorized devices only
{Colors.ENDC}
"""
    print(banner)


class ESP32CamAttacker:
    """Simulates various attacks against ESP32-CAM device."""

    def __init__(self, target_ip: str, dashboard_url: str = "http://localhost:5000"):
        self.target_ip = target_ip
        self.dashboard_url = dashboard_url
        self.attack_log = []
        self.start_time = datetime.now()

    def log_attack(self, attack_type: str, status: str, details: str = ""):
        """Log attack attempt."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "attack_type": attack_type,
            "status": status,
            "details": details
        }
        self.attack_log.append(log_entry)

        status_color = Colors.OKGREEN if status == "SUCCESS" else Colors.FAIL
        print(f"[{timestamp}] {Colors.BOLD}{attack_type:30}{Colors.ENDC} {status_color}{status:10}{Colors.ENDC} {details}")

    def check_device_status(self) -> Dict:
        """Check if device is isolated via RAKSHAK API."""
        try:
            response = requests.get(f"{self.dashboard_url}/api/devices/{self.target_ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    device = data.get("data", {})
                    return {
                        "reachable": True,
                        "status": device.get("status", "unknown"),
                        "isolated": device.get("status") == "isolated",
                        "risk_score": device.get("risk_score", 0)
                    }
        except Exception as e:
            pass

        return {"reachable": False, "status": "unknown", "isolated": False, "risk_score": 0}

    def ping_device(self) -> bool:
        """Check if device responds to ping."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", self.target_ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False

    # =========================================================================
    # ATTACK 1: Basic Port Scanning (TCP Connect Scan)
    # =========================================================================
    def attack_tcp_connect_scan(self):
        """Perform basic TCP connect scan - most detectable."""
        print(f"\n{Colors.HEADER}{'='*76}")
        print(f"ATTACK 1: TCP Connect Scan (Noisy, Easily Detected)")
        print(f"{'='*76}{Colors.ENDC}\n")

        try:
            cmd = ["nmap", "-sT", "-p", "1-1000", "-T4", self.target_ip]
            self.log_attack("TCP Connect Scan", "STARTING", f"nmap -sT -p 1-1000 {self.target_ip}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                open_ports = [line for line in result.stdout.split('\n') if '/tcp' in line and 'open' in line]
                self.log_attack("TCP Connect Scan", "SUCCESS", f"Found {len(open_ports)} open port(s)")
                print(f"\n{Colors.OKGREEN}Open Ports:{Colors.ENDC}")
                for port_line in open_ports:
                    print(f"  {port_line}")
            else:
                self.log_attack("TCP Connect Scan", "FAILED", "Scan failed")

        except subprocess.TimeoutExpired:
            self.log_attack("TCP Connect Scan", "TIMEOUT", "Scan timed out (device may be isolated)")
        except Exception as e:
            self.log_attack("TCP Connect Scan", "ERROR", str(e))

    # =========================================================================
    # ATTACK 2: SYN Stealth Scan (requires root)
    # =========================================================================
    def attack_syn_scan(self):
        """Perform SYN stealth scan - harder to detect."""
        print(f"\n{Colors.HEADER}{'='*76}")
        print(f"ATTACK 2: SYN Stealth Scan (Requires Root)")
        print(f"{'='*76}{Colors.ENDC}\n")

        if os.geteuid() != 0:
            self.log_attack("SYN Stealth Scan", "SKIPPED", "Requires root privileges")
            print(f"{Colors.WARNING}⚠️  Skipping SYN scan (run with sudo for this attack){Colors.ENDC}")
            return

        try:
            cmd = ["nmap", "-sS", "-p", "1-1000", "-T4", self.target_ip]
            self.log_attack("SYN Stealth Scan", "STARTING", f"nmap -sS -p 1-1000 {self.target_ip}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                open_ports = [line for line in result.stdout.split('\n') if '/tcp' in line and 'open' in line]
                self.log_attack("SYN Stealth Scan", "SUCCESS", f"Found {len(open_ports)} open port(s)")
            else:
                self.log_attack("SYN Stealth Scan", "FAILED", "Scan failed")

        except subprocess.TimeoutExpired:
            self.log_attack("SYN Stealth Scan", "TIMEOUT", "Scan timed out (device may be isolated)")
        except Exception as e:
            self.log_attack("SYN Stealth Scan", "ERROR", str(e))

    # =========================================================================
    # ATTACK 3: Aggressive Service Detection
    # =========================================================================
    def attack_service_detection(self):
        """Aggressive service and OS detection."""
        print(f"\n{Colors.HEADER}{'='*76}")
        print(f"ATTACK 3: Aggressive Service & OS Detection")
        print(f"{'='*76}{Colors.ENDC}\n")

        try:
            cmd = ["nmap", "-sV", "-O", "--osscan-guess", "-p", "80,8080,23,22,554", self.target_ip]
            self.log_attack("Service Detection", "STARTING", "nmap -sV -O (aggressive)")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            if result.returncode == 0:
                self.log_attack("Service Detection", "SUCCESS", "Service enumeration complete")
                # Extract service info
                for line in result.stdout.split('\n'):
                    if 'http' in line.lower() or 'open' in line.lower():
                        print(f"  {line}")
            else:
                self.log_attack("Service Detection", "FAILED", "Detection failed")

        except subprocess.TimeoutExpired:
            self.log_attack("Service Detection", "TIMEOUT", "Scan timed out (device may be isolated)")
        except Exception as e:
            self.log_attack("Service Detection", "ERROR", str(e))

    # =========================================================================
    # ATTACK 4: Repeated HTTP Access (Unauthorized Stream Access)
    # =========================================================================
    def attack_repeated_http_access(self, count: int = 50):
        """Simulate unauthorized repeated access to camera stream."""
        print(f"\n{Colors.HEADER}{'='*76}")
        print(f"ATTACK 4: Repeated Unauthorized HTTP Access ({count} requests)")
        print(f"{'='*76}{Colors.ENDC}\n")

        self.log_attack("HTTP Access Attack", "STARTING", f"Attempting {count} unauthorized stream accesses")

        success_count = 0
        failed_count = 0

        for i in range(count):
            try:
                # Try to access camera stream
                response = requests.get(f"http://{self.target_ip}/stream", timeout=2, stream=True)

                if response.status_code == 200:
                    success_count += 1
                    # Read a small chunk
                    chunk = next(response.iter_content(chunk_size=1024), None)
                    if i % 10 == 0:
                        print(f"  [{i+1}/{count}] Stream accessed ({len(chunk) if chunk else 0} bytes)")
                else:
                    failed_count += 1

                response.close()
                time.sleep(0.1)  # Small delay between requests

            except requests.exceptions.RequestException as e:
                failed_count += 1
                if i % 10 == 0:
                    print(f"  [{i+1}/{count}] Failed: {e}")
                time.sleep(0.5)

        self.log_attack("HTTP Access Attack", "COMPLETED",
                       f"Success: {success_count}, Failed: {failed_count}")

    # =========================================================================
    # ATTACK 5: Banner Grabbing on Multiple Ports
    # =========================================================================
    def attack_banner_grab(self):
        """Attempt to grab service banners from common ports."""
        print(f"\n{Colors.HEADER}{'='*76}")
        print(f"ATTACK 5: Banner Grabbing (Information Disclosure)")
        print(f"{'='*76}{Colors.ENDC}\n")

        common_ports = [80, 8080, 23, 22, 21, 554, 8554]
        self.log_attack("Banner Grabbing", "STARTING", f"Testing {len(common_ports)} ports")

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target_ip, port))

                if result == 0:
                    print(f"  Port {port:5d}: {Colors.OKGREEN}OPEN{Colors.ENDC}", end="")

                    # Try to grab banner
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            print(f" - Banner: {banner[:50]}")
                        else:
                            print()
                    except:
                        print()
                else:
                    print(f"  Port {port:5d}: CLOSED")

                sock.close()
                time.sleep(0.2)

            except Exception as e:
                print(f"  Port {port:5d}: ERROR - {e}")

        self.log_attack("Banner Grabbing", "COMPLETED", "Scan finished")

    # =========================================================================
    # ATTACK 6: Rapid Connection Flood
    # =========================================================================
    def attack_connection_flood(self, count: int = 100):
        """Flood device with rapid connection attempts."""
        print(f"\n{Colors.HEADER}{'='*76}")
        print(f"ATTACK 6: Connection Flood ({count} rapid connections)")
        print(f"{'='*76}{Colors.ENDC}\n")

        self.log_attack("Connection Flood", "STARTING", f"Initiating {count} rapid connections")

        success = 0
        failed = 0

        for i in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_ip, 80))
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                sock.recv(100)
                sock.close()
                success += 1

                if i % 20 == 0:
                    print(f"  [{i+1}/{count}] Connections sent...")

            except:
                failed += 1

            time.sleep(0.05)  # Very small delay for flooding effect

        self.log_attack("Connection Flood", "COMPLETED", f"Success: {success}, Failed: {failed}")

    # =========================================================================
    # Monitoring Thread
    # =========================================================================
    def monitor_device_status(self, duration: int = 300):
        """Monitor device isolation status during attacks."""
        print(f"\n{Colors.OKCYAN}{'='*76}")
        print(f"Starting Monitoring Thread (Duration: {duration}s)")
        print(f"{'='*76}{Colors.ENDC}\n")

        start_time = time.time()
        last_status = None

        while time.time() - start_time < duration:
            status = self.check_device_status()

            if status != last_status:
                timestamp = datetime.now().strftime("%H:%M:%S")

                if status.get("isolated"):
                    print(f"\n{Colors.FAIL}{'='*76}")
                    print(f"🚨 [{timestamp}] DEVICE ISOLATED BY RAKSHAK!")
                    print(f"{'='*76}{Colors.ENDC}")
                    print(f"  Status: {status.get('status')}")
                    print(f"  Risk Score: {status.get('risk_score')}%")
                    print(f"  Duration: {int(time.time() - start_time)}s since attack start\n")
                    return True  # Attack detected and mitigated!

                last_status = status

            time.sleep(5)

        return False

    # =========================================================================
    # Main Attack Sequence
    # =========================================================================
    def run_attack_sequence(self, attacks: List[str] = None):
        """Execute attack sequence."""

        if attacks is None:
            attacks = ["tcp_scan", "http_flood", "banner_grab", "connection_flood"]

        print(f"{Colors.OKBLUE}Initial device check...{Colors.ENDC}")
        initial_status = self.check_device_status()
        print(f"  Device Status: {initial_status.get('status', 'unknown')}")
        print(f"  Risk Score: {initial_status.get('risk_score', 0)}%")
        print(f"  Isolated: {initial_status.get('isolated', False)}")

        if not self.ping_device():
            print(f"\n{Colors.WARNING}⚠️  Device not responding to ping. May already be isolated.{Colors.ENDC}")
            return

        print(f"\n{Colors.OKGREEN}✓ Device is reachable. Starting attack sequence...{Colors.ENDC}")
        time.sleep(2)

        # Start monitoring in background
        monitor_thread = threading.Thread(
            target=self.monitor_device_status,
            args=(300,),  # Monitor for 5 minutes
            daemon=True
        )
        monitor_thread.start()

        # Execute attacks
        attack_map = {
            "tcp_scan": self.attack_tcp_connect_scan,
            "syn_scan": self.attack_syn_scan,
            "service_detect": self.attack_service_detection,
            "http_flood": self.attack_repeated_http_access,
            "banner_grab": self.attack_banner_grab,
            "connection_flood": self.attack_connection_flood
        }

        for attack_name in attacks:
            if attack_name in attack_map:
                attack_map[attack_name]()

                # Check status after each attack
                time.sleep(3)
                status = self.check_device_status()

                if status.get("isolated"):
                    print(f"\n{Colors.FAIL}{'='*76}")
                    print(f"🎯 SUCCESS! Device isolated after {attack_name}")
                    print(f"{'='*76}{Colors.ENDC}\n")
                    break
                else:
                    print(f"{Colors.OKCYAN}  Device still active (Risk: {status.get('risk_score', 0)}%){Colors.ENDC}")

                time.sleep(2)

        # Final status
        self.print_summary()

    def print_summary(self):
        """Print attack summary."""
        print(f"\n{Colors.HEADER}{'='*76}")
        print(f"ATTACK SUMMARY")
        print(f"{'='*76}{Colors.ENDC}\n")

        final_status = self.check_device_status()

        print(f"{Colors.BOLD}Final Device Status:{Colors.ENDC}")
        print(f"  Status: {final_status.get('status', 'unknown')}")
        print(f"  Isolated: {final_status.get('isolated', False)}")
        print(f"  Risk Score: {final_status.get('risk_score', 0)}%")

        print(f"\n{Colors.BOLD}Attack Log:{Colors.ENDC}")
        for entry in self.attack_log:
            print(f"  [{entry['timestamp']}] {entry['attack_type']:30} {entry['status']:10} {entry['details']}")

        duration = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{Colors.BOLD}Total Duration:{Colors.ENDC} {duration:.1f} seconds")

        if final_status.get("isolated"):
            print(f"\n{Colors.OKGREEN}{'='*76}")
            print(f"✅ RAKSHAK SUCCESSFULLY DETECTED AND ISOLATED THE DEVICE!")
            print(f"{'='*76}{Colors.ENDC}\n")
        else:
            print(f"\n{Colors.WARNING}{'='*76}")
            print(f"⚠️  Device was not isolated. Check RAKSHAK logs for detection status.")
            print(f"{'='*76}{Colors.ENDC}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ESP32-CAM Attack Simulation for RAKSHAK Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all attacks
  sudo python3 attack_esp32cam.py

  # Run specific attacks
  python3 attack_esp32cam.py --attacks tcp_scan,http_flood

  # Custom target
  python3 attack_esp32cam.py --target 10.42.0.136

Available Attacks:
  tcp_scan          - Basic TCP connect scan (noisy, easily detected)
  syn_scan          - SYN stealth scan (requires root)
  service_detect    - Aggressive service/OS detection
  http_flood        - Repeated unauthorized HTTP access
  banner_grab       - Banner grabbing on multiple ports
  connection_flood  - Rapid connection flooding
        """
    )

    parser.add_argument(
        "--target",
        default="10.42.0.103",
        help="Target ESP32-CAM IP address (default: 10.42.0.103)"
    )

    parser.add_argument(
        "--dashboard",
        default="http://localhost:5000",
        help="RAKSHAK dashboard URL (default: http://localhost:5000)"
    )

    parser.add_argument(
        "--attacks",
        help="Comma-separated list of attacks to run (default: all)"
    )

    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick test mode (fewer requests)"
    )

    args = parser.parse_args()

    print_banner()

    # Parse attack list
    if args.attacks:
        attacks = [a.strip() for a in args.attacks.split(",")]
    else:
        attacks = None  # Run all

    # Create attacker
    attacker = ESP32CamAttacker(args.target, args.dashboard)

    # Confirm before starting
    print(f"{Colors.WARNING}This will perform real security testing attacks.{Colors.ENDC}")
    print(f"Target: {args.target}")

    if os.geteuid() != 0:
        print(f"\n{Colors.WARNING}⚠️  Not running as root. Some attacks (SYN scan) will be skipped.{Colors.ENDC}")
        print(f"Run with 'sudo' for full attack simulation.\n")

    confirm = input(f"\n{Colors.BOLD}Continue? (yes/no): {Colors.ENDC}")
    if confirm.lower() != "yes":
        print("Aborted.")
        return

    print(f"\n{Colors.OKGREEN}Starting attack sequence in 3 seconds...{Colors.ENDC}")
    time.sleep(3)

    # Run attacks
    attacker.run_attack_sequence(attacks)


if __name__ == "__main__":
    main()
