#!/bin/bash
# RAKSHAK Gateway Cleanup Script
# Reverses all network changes made by start_rakshak.sh

set -e

# Variables (must match start_rakshak.sh)
WAN_IF="wlo1"     # WiFi interface (internet)
LAN_IF="enx207bd51a6a7d"  # USB Ethernet interface (to router in AP mode)
LAN_IP="192.168.100.1"

echo "=========================================="
echo "  RAKSHAK Gateway Cleanup"
echo "=========================================="

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

# Step 1: Stop DHCP server
echo "[1/4] Stopping DHCP server..."
pkill dnsmasq 2>/dev/null && echo "  dnsmasq stopped" || echo "  dnsmasq not running"

# Step 2: Remove NAT rules
echo "[2/4] Removing NAT rules..."
iptables -t nat -D POSTROUTING -o $WAN_IF -j MASQUERADE 2>/dev/null && echo "  Removed MASQUERADE rule" || echo "  MASQUERADE rule not found"
iptables -D FORWARD -i $LAN_IF -o $WAN_IF -j ACCEPT 2>/dev/null && echo "  Removed FORWARD rule (LAN->WAN)" || echo "  FORWARD rule not found"
iptables -D FORWARD -i $WAN_IF -o $LAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && echo "  Removed FORWARD rule (WAN->LAN)" || echo "  FORWARD rule not found"

# Step 3: Remove LAN IP
echo "[3/4] Removing LAN IP from $LAN_IF..."
ip addr del $LAN_IP/24 dev $LAN_IF 2>/dev/null && echo "  IP removed" || echo "  IP not assigned"

# Step 4: Optionally disable IP forwarding
echo "[4/4] Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0 > /dev/null
rm -f /etc/sysctl.d/99-rakshak.conf 2>/dev/null || true

echo ""
echo "=========================================="
echo "  Cleanup complete!"
echo "=========================================="
echo "Your network is restored to normal state."
echo "=========================================="
