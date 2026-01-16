#!/bin/bash
# RAKSHAK Startup Script
# Ubuntu Laptop with NetworkManager Connection Sharing

set -e

# Variables
LAN_IF="enx207bd51a6a7d"  # USB Ethernet interface (to router in AP mode)
LAN_NETWORK="10.42.0.0/24"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "  RAKSHAK Startup"
echo "=========================================="
echo "LAN Interface: $LAN_IF"
echo "LAN Network: $LAN_NETWORK"
echo "=========================================="
echo ""
echo "Note: NetworkManager handles gateway/DHCP"
echo ""

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

# Check if interface is up
if ip link show $LAN_IF | grep -q "state UP"; then
    echo "[OK] LAN interface $LAN_IF is UP"
else
    echo "[WARNING] LAN interface $LAN_IF is DOWN"
fi

# Check connected devices
echo ""
echo "Connected devices:"
ip neigh show dev $LAN_IF 2>/dev/null | grep -v FAILED || echo "  No devices found yet"
echo ""
echo ""
echo "=========================================="
echo "  Starting RAKSHAK..."
echo "=========================================="
echo "Dashboard will be available at:"
echo "  - http://localhost:5000"
echo "  - http://$LAN_IP:5000"
echo "=========================================="
echo ""

# Step 5: Start RAKSHAK
cd "$SCRIPT_DIR"

# Use the venv Python with current sudo session
if [ -f "venv/bin/python" ]; then
    exec venv/bin/python main.py
else
    exec python3 main.py
fi
