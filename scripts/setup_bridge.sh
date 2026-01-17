#!/bin/bash
# =============================================================================
# RAKSHAK Bridge Mode Setup Script
# =============================================================================
# This script configures a Layer-2 bridge (br0) for full traffic visibility.
#
# Usage:
#   sudo ./setup_bridge.sh --start    # Create bridge and configure
#   sudo ./setup_bridge.sh --stop     # Remove bridge (rollback)
#   sudo ./setup_bridge.sh --status   # Show bridge status
#   sudo ./setup_bridge.sh --verify   # Verify bridge is working
#
# Architecture:
#   Internet -> Modem -> [eth_wan] Jetson [br0] -> Router (AP) -> Devices
#                                    |
#                              eth_lan (member)
#
# Bridge mode enables:
#   - Layer-2 visibility (all ARP, broadcast traffic)
#   - Passive device discovery (SSDP, ONVIF, RTSP)
#   - Static IP device detection
#   - Full traffic inspection via iptables
#
# =============================================================================

set -e

# Configuration (can be overridden by environment variables)
BRIDGE_NAME="${BRIDGE_NAME:-br0}"
ETH_LAN="${ETH_LAN:-enx207bd51a6a7d}"
ETH_WAN="${ETH_WAN:-wlo1}"
BRIDGE_IP="${BRIDGE_IP:-10.42.0.1}"
BRIDGE_NETMASK="${BRIDGE_NETMASK:-24}"
DHCP_RANGE_START="${DHCP_RANGE_START:-10.42.0.10}"
DHCP_RANGE_END="${DHCP_RANGE_END:-10.42.0.254}"
DHCP_LEASE_TIME="${DHCP_LEASE_TIME:-24h}"
DNS_SERVER_1="${DNS_SERVER_1:-8.8.8.8}"
DNS_SERVER_2="${DNS_SERVER_2:-1.1.1.1}"

# Paths
DNSMASQ_CONFIG="/etc/dnsmasq.d/rakshak-bridge.conf"
SYSCTL_CONFIG="/etc/sysctl.d/99-rakshak-bridge.conf"
LOG_FILE="/var/log/rakshak-bridge.log"
STATE_FILE="/var/run/rakshak-bridge.state"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: $1" >> "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

print_banner() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "     RAKSHAK LAYER-2 BRIDGE MODE"
    echo "     Full Traffic Visibility + Layer-3 Gateway"
    echo "============================================================"
    echo -e "${NC}"
}

# -----------------------------------------------------------------------------
# Check Prerequisites
# -----------------------------------------------------------------------------
check_prerequisites() {
    log_info "Checking prerequisites..."
    ERRORS=0

    # Check root
    if [ "$EUID" -ne 0 ]; then
        log_error "Must run as root (use: sudo $0)"
        ERRORS=$((ERRORS + 1))
    fi

    # Check required tools
    REQUIRED_TOOLS="ip bridge iptables dnsmasq sysctl modprobe"
    for tool in $REQUIRED_TOOLS; do
        if ! command -v $tool &> /dev/null; then
            log_error "Missing required tool: $tool"
            ERRORS=$((ERRORS + 1))
        fi
    done

    # Check if member interface exists
    if ! ip link show "$ETH_LAN" &> /dev/null; then
        log_error "LAN interface $ETH_LAN not found"
        log_info "Available interfaces:"
        ip -o link show | awk -F': ' '{print "  " $2}'
        ERRORS=$((ERRORS + 1))
    else
        log_success "LAN interface $ETH_LAN found"
    fi

    # Check if WAN interface exists and has connectivity
    if ip link show "$ETH_WAN" &> /dev/null; then
        if ip addr show "$ETH_WAN" | grep -q "inet "; then
            WAN_IP=$(ip addr show "$ETH_WAN" | grep "inet " | awk '{print $2}' | head -1)
            log_success "WAN interface $ETH_WAN has IP: $WAN_IP"
        else
            log_warning "WAN interface $ETH_WAN has no IP"
        fi
    else
        log_warning "WAN interface $ETH_WAN not found"
    fi

    if [ $ERRORS -eq 0 ]; then
        log_success "All prerequisites met"
        return 0
    else
        log_error "Prerequisites check failed with $ERRORS errors"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Load Bridge Kernel Module
# -----------------------------------------------------------------------------
load_bridge_module() {
    log_info "Loading bridge kernel module..."

    # Load br_netfilter for iptables on bridge
    if ! lsmod | grep -q "br_netfilter"; then
        modprobe br_netfilter
        if [ $? -eq 0 ]; then
            log_success "br_netfilter module loaded"
        else
            log_error "Failed to load br_netfilter module"
            return 1
        fi
    else
        log_info "br_netfilter module already loaded"
    fi

    # Load bridge module
    if ! lsmod | grep -q "^bridge"; then
        modprobe bridge
    fi

    return 0
}

# -----------------------------------------------------------------------------
# Enable Kernel Settings for Bridge
# -----------------------------------------------------------------------------
enable_kernel_settings() {
    log_info "Enabling kernel settings for bridge mode..."

    # Create sysctl config
    mkdir -p "$(dirname "$SYSCTL_CONFIG")"
    cat > "$SYSCTL_CONFIG" << EOF
# =============================================================================
# RAKSHAK Bridge Mode - Kernel Settings
# Generated: $(date)
# =============================================================================

# Enable IPv4 forwarding (MANDATORY)
net.ipv4.ip_forward=1

# Enable iptables processing of bridged traffic (CRITICAL for security)
# This allows iptables rules to apply to packets traversing the bridge
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-arptables=1
net.bridge.bridge-nf-call-ip6tables=0

# Enable proxy ARP on bridge (for routing)
net.ipv4.conf.all.proxy_arp=1
net.ipv4.conf.${BRIDGE_NAME}.proxy_arp=1

# Disable IPv6 forwarding
net.ipv6.conf.all.forwarding=0

# Security settings
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Log martians
net.ipv4.conf.all.log_martians=1
EOF

    # Apply settings immediately
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.bridge.bridge-nf-call-iptables=1 > /dev/null 2>&1 || true
    sysctl -w net.bridge.bridge-nf-call-arptables=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.proxy_arp=1 > /dev/null

    # Apply from file
    sysctl -p "$SYSCTL_CONFIG" > /dev/null 2>&1 || true

    # Verify critical settings
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
        log_success "IP forwarding enabled"
    else
        log_error "Failed to enable IP forwarding"
        return 1
    fi

    if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
        if [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = "1" ]; then
            log_success "bridge-nf-call-iptables enabled"
        else
            log_warning "bridge-nf-call-iptables not enabled (bridge may need to be created first)"
        fi
    fi

    return 0
}

# -----------------------------------------------------------------------------
# Save Current State (for rollback)
# -----------------------------------------------------------------------------
save_state() {
    log_info "Saving current state for rollback..."

    mkdir -p "$(dirname "$STATE_FILE")"

    # Save current interface configuration
    cat > "$STATE_FILE" << EOF
# RAKSHAK Bridge State - $(date)
ORIGINAL_LAN_INTERFACE=$ETH_LAN
ORIGINAL_LAN_IP=$(ip addr show "$ETH_LAN" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
BRIDGE_NAME=$BRIDGE_NAME
BRIDGE_IP=$BRIDGE_IP/$BRIDGE_NETMASK
EOF

    log_success "State saved to $STATE_FILE"
}

# -----------------------------------------------------------------------------
# Create Bridge
# -----------------------------------------------------------------------------
create_bridge() {
    log_info "Creating Layer-2 bridge $BRIDGE_NAME..."

    # Check if bridge already exists
    if ip link show "$BRIDGE_NAME" &> /dev/null; then
        log_warning "Bridge $BRIDGE_NAME already exists"

        # Check if it has correct members
        if bridge link show | grep -q "$ETH_LAN"; then
            log_info "Bridge already has $ETH_LAN as member"
            return 0
        fi
    fi

    # Save state before making changes
    save_state

    # Step 1: Flush IP from member interface
    log_info "Removing IP from $ETH_LAN..."
    ip addr flush dev "$ETH_LAN" 2>/dev/null || true

    # Step 2: Create bridge interface
    if ! ip link show "$BRIDGE_NAME" &> /dev/null; then
        ip link add name "$BRIDGE_NAME" type bridge
        log_success "Bridge $BRIDGE_NAME created"
    fi

    # Step 3: Add member interface to bridge
    ip link set "$ETH_LAN" master "$BRIDGE_NAME"
    log_success "Added $ETH_LAN to bridge $BRIDGE_NAME"

    # Step 4: Bring up interfaces
    ip link set "$ETH_LAN" up
    ip link set "$BRIDGE_NAME" up
    log_success "Interfaces are up"

    # Step 5: Assign IP to bridge
    ip addr add "$BRIDGE_IP/$BRIDGE_NETMASK" dev "$BRIDGE_NAME" 2>/dev/null || {
        # IP might already be assigned
        if ip addr show "$BRIDGE_NAME" | grep -q "$BRIDGE_IP"; then
            log_info "IP $BRIDGE_IP already assigned to $BRIDGE_NAME"
        else
            log_error "Failed to assign IP to bridge"
            return 1
        fi
    }

    log_success "Bridge $BRIDGE_NAME configured with IP $BRIDGE_IP/$BRIDGE_NETMASK"

    # Re-apply bridge-nf settings now that bridge exists
    sysctl -w net.bridge.bridge-nf-call-iptables=1 > /dev/null 2>&1 || true
    sysctl -w net.bridge.bridge-nf-call-arptables=1 > /dev/null 2>&1 || true
    sysctl -w "net.ipv4.conf.${BRIDGE_NAME}.proxy_arp=1" > /dev/null 2>&1 || true

    return 0
}

# -----------------------------------------------------------------------------
# Configure dnsmasq for Bridge
# -----------------------------------------------------------------------------
configure_dnsmasq() {
    log_info "Configuring DHCP server (dnsmasq) for bridge..."

    # Stop dnsmasq if running
    systemctl stop dnsmasq 2>/dev/null || true

    # Create configuration
    mkdir -p /etc/dnsmasq.d
    cat > "$DNSMASQ_CONFIG" << EOF
# =============================================================================
# RAKSHAK Bridge Mode - DHCP/DNS Configuration
# Generated: $(date)
# =============================================================================

# Bind ONLY to bridge interface (CRITICAL)
interface=$BRIDGE_NAME
bind-interfaces

# Don't use /etc/resolv.conf
no-resolv

# Upstream DNS servers
server=$DNS_SERVER_1
server=$DNS_SERVER_2

# DHCP range
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$DHCP_LEASE_TIME

# Gateway (bridge interface)
dhcp-option=option:router,$BRIDGE_IP

# DNS server (this device)
dhcp-option=option:dns-server,$BRIDGE_IP

# Domain
domain=rakshak.local
local=/rakshak.local/

# DHCP lease file
dhcp-leasefile=/var/lib/misc/dnsmasq.leases

# Log DHCP for device discovery
log-dhcp

# Expand hostnames
expand-hosts
EOF

    # Ensure lease directory exists
    mkdir -p /var/lib/misc
    touch /var/lib/misc/dnsmasq.leases
    chmod 644 /var/lib/misc/dnsmasq.leases

    # Start dnsmasq
    systemctl enable dnsmasq 2>/dev/null || true
    systemctl start dnsmasq

    # Verify
    sleep 1
    if systemctl is-active --quiet dnsmasq; then
        log_success "dnsmasq started and bound to $BRIDGE_NAME"
        return 0
    else
        log_error "Failed to start dnsmasq"
        systemctl status dnsmasq --no-pager || true
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Setup NAT Rules for Bridge
# -----------------------------------------------------------------------------
setup_nat_for_bridge() {
    log_info "Setting up NAT rules for bridge mode..."

    # Create RAKSHAK chains if they don't exist
    iptables -N RAKSHAK_FORWARD 2>/dev/null || iptables -F RAKSHAK_FORWARD
    iptables -N RAKSHAK_ISOLATED 2>/dev/null || iptables -F RAKSHAK_ISOLATED
    iptables -N RAKSHAK_RATELIMIT 2>/dev/null || iptables -F RAKSHAK_RATELIMIT
    iptables -t nat -N RAKSHAK_HONEYPOT 2>/dev/null || iptables -t nat -F RAKSHAK_HONEYPOT

    # Remove old jumps (cleanup)
    for i in $(seq 1 5); do
        iptables -D FORWARD -j RAKSHAK_ISOLATED 2>/dev/null || true
        iptables -D FORWARD -j RAKSHAK_RATELIMIT 2>/dev/null || true
        iptables -D FORWARD -j RAKSHAK_FORWARD 2>/dev/null || true
        iptables -t nat -D PREROUTING -j RAKSHAK_HONEYPOT 2>/dev/null || true
    done

    # Insert jumps to RAKSHAK chains
    iptables -I FORWARD 1 -j RAKSHAK_ISOLATED
    iptables -I FORWARD 2 -j RAKSHAK_RATELIMIT
    iptables -I FORWARD 3 -j RAKSHAK_FORWARD
    iptables -t nat -I PREROUTING 1 -j RAKSHAK_HONEYPOT

    # NAT: Masquerade outgoing traffic on WAN
    # Remove old masquerade rules first
    iptables -t nat -D POSTROUTING -o "$ETH_WAN" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -A POSTROUTING -o "$ETH_WAN" -j MASQUERADE

    # FORWARD: Allow traffic from bridge to WAN
    iptables -A RAKSHAK_FORWARD -i "$BRIDGE_NAME" -o "$ETH_WAN" -j ACCEPT

    # FORWARD: Allow established/related traffic back
    iptables -A RAKSHAK_FORWARD -i "$ETH_WAN" -o "$BRIDGE_NAME" \
        -m state --state RELATED,ESTABLISHED -j ACCEPT

    # INPUT: Allow DHCP on bridge
    iptables -A INPUT -i "$BRIDGE_NAME" -p udp --dport 67:68 -j ACCEPT

    # INPUT: Allow DNS on bridge
    iptables -A INPUT -i "$BRIDGE_NAME" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$BRIDGE_NAME" -p tcp --dport 53 -j ACCEPT

    # INPUT: Allow RAKSHAK dashboard
    iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

    # INPUT: Allow honeypot ports
    iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
    iptables -A INPUT -p tcp --dport 2323 -j ACCEPT
    iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

    log_success "NAT rules configured for bridge mode"
}

# -----------------------------------------------------------------------------
# Remove Bridge (Rollback)
# -----------------------------------------------------------------------------
remove_bridge() {
    log_info "Removing bridge $BRIDGE_NAME (rollback)..."

    # Read saved state if available
    if [ -f "$STATE_FILE" ]; then
        source "$STATE_FILE"
        log_info "Loaded state from $STATE_FILE"
    fi

    # Step 1: Stop dnsmasq
    systemctl stop dnsmasq 2>/dev/null || true

    # Step 2: Flush IP from bridge
    ip addr flush dev "$BRIDGE_NAME" 2>/dev/null || true

    # Step 3: Remove member from bridge
    ip link set "$ETH_LAN" nomaster 2>/dev/null || true

    # Step 4: Delete bridge
    ip link set "$BRIDGE_NAME" down 2>/dev/null || true
    ip link delete "$BRIDGE_NAME" type bridge 2>/dev/null || true

    # Step 5: Restore IP to original interface
    if [ -n "$ORIGINAL_LAN_IP" ] && [ "$ORIGINAL_LAN_IP" != "" ]; then
        ip addr add "$ORIGINAL_LAN_IP" dev "$ETH_LAN" 2>/dev/null || true
    else
        # Default: assign bridge IP to original interface
        ip addr add "$BRIDGE_IP/$BRIDGE_NETMASK" dev "$ETH_LAN" 2>/dev/null || true
    fi
    ip link set "$ETH_LAN" up

    # Step 6: Update dnsmasq to use original interface
    if [ -f "$DNSMASQ_CONFIG" ]; then
        sed -i "s/interface=.*/interface=$ETH_LAN/" "$DNSMASQ_CONFIG"
        systemctl start dnsmasq 2>/dev/null || true
    fi

    # Step 7: Cleanup config files
    rm -f "$SYSCTL_CONFIG" 2>/dev/null || true
    rm -f "$STATE_FILE" 2>/dev/null || true

    log_success "Bridge removed, restored to direct interface mode"
}

# -----------------------------------------------------------------------------
# Verify Bridge
# -----------------------------------------------------------------------------
verify_bridge() {
    echo ""
    echo "============================================================"
    echo "     RAKSHAK BRIDGE VERIFICATION"
    echo "============================================================"
    echo ""

    ERRORS=0
    WARNINGS=0

    # Check 1: Bridge exists
    echo -n "1. Bridge $BRIDGE_NAME exists: "
    if ip link show "$BRIDGE_NAME" &> /dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        ERRORS=$((ERRORS + 1))
    fi

    # Check 2: Bridge has IP
    echo -n "2. Bridge has IP $BRIDGE_IP: "
    if ip addr show "$BRIDGE_NAME" 2>/dev/null | grep -q "$BRIDGE_IP"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        ERRORS=$((ERRORS + 1))
    fi

    # Check 3: Bridge is UP
    echo -n "3. Bridge state is UP: "
    if ip link show "$BRIDGE_NAME" 2>/dev/null | grep -q "state UP"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}WARN${NC} (state may be UNKNOWN for bridge)"
        WARNINGS=$((WARNINGS + 1))
    fi

    # Check 4: Member interface attached
    echo -n "4. $ETH_LAN is bridge member: "
    if bridge link show 2>/dev/null | grep -q "$ETH_LAN"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        ERRORS=$((ERRORS + 1))
    fi

    # Check 5: bridge-nf-call-iptables enabled
    echo -n "5. bridge-nf-call-iptables: "
    if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
        if [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = "1" ]; then
            echo -e "${GREEN}OK (enabled)${NC}"
        else
            echo -e "${RED}FAIL (disabled)${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${YELLOW}WARN (file not found)${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi

    # Check 6: IP forwarding
    echo -n "6. IP forwarding enabled: "
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        ERRORS=$((ERRORS + 1))
    fi

    # Check 7: dnsmasq running
    echo -n "7. dnsmasq running: "
    if systemctl is-active --quiet dnsmasq; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        ERRORS=$((ERRORS + 1))
    fi

    # Check 8: dnsmasq bound to bridge
    echo -n "8. dnsmasq bound to $BRIDGE_NAME: "
    if grep -q "interface=$BRIDGE_NAME" "$DNSMASQ_CONFIG" 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}WARN (check config)${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi

    # Check 9: RAKSHAK firewall chains
    echo -n "9. RAKSHAK_FORWARD chain: "
    if iptables -L RAKSHAK_FORWARD -n &> /dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}WARN (not created)${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi

    # Check 10: NAT MASQUERADE
    echo -n "10. NAT MASQUERADE on $ETH_WAN: "
    if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE.*$ETH_WAN"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}WARN (check rules)${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi

    # Summary
    echo ""
    echo "============================================================"
    if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}All checks passed!${NC}"
    elif [ $ERRORS -eq 0 ]; then
        echo -e "${YELLOW}$WARNINGS warnings, but no critical errors${NC}"
    else
        echo -e "${RED}$ERRORS errors, $WARNINGS warnings${NC}"
    fi
    echo "============================================================"
    echo ""

    # Show bridge info
    echo "Bridge Details:"
    bridge link show 2>/dev/null || echo "  (bridge command failed)"
    echo ""
    echo "Bridge Forwarding Database:"
    bridge fdb show br "$BRIDGE_NAME" 2>/dev/null | head -10 || echo "  (no entries)"
    echo ""

    return $ERRORS
}

# -----------------------------------------------------------------------------
# Show Status
# -----------------------------------------------------------------------------
show_status() {
    echo ""
    echo "============================================================"
    echo "     RAKSHAK BRIDGE STATUS"
    echo "============================================================"
    echo ""

    # Bridge info
    echo "Bridge Interface:"
    if ip link show "$BRIDGE_NAME" &> /dev/null; then
        BRIDGE_STATE=$(ip link show "$BRIDGE_NAME" | grep -o "state [A-Z]*" | awk '{print $2}')
        BRIDGE_MAC=$(ip link show "$BRIDGE_NAME" | grep "link/ether" | awk '{print $2}')
        BRIDGE_ACTUAL_IP=$(ip addr show "$BRIDGE_NAME" | grep "inet " | awk '{print $2}')
        echo -e "  Name: ${GREEN}$BRIDGE_NAME${NC}"
        echo "  State: $BRIDGE_STATE"
        echo "  MAC: $BRIDGE_MAC"
        echo "  IP: $BRIDGE_ACTUAL_IP"
    else
        echo -e "  ${RED}Bridge $BRIDGE_NAME not found${NC}"
    fi

    # Member interfaces
    echo ""
    echo "Bridge Members:"
    if bridge link show 2>/dev/null | grep -q "$BRIDGE_NAME"; then
        bridge link show 2>/dev/null | grep "$BRIDGE_NAME" | while read line; do
            MEMBER=$(echo "$line" | awk '{print $2}' | cut -d: -f1)
            echo "  - $MEMBER"
        done
    else
        echo "  No members attached"
    fi

    # Kernel settings
    echo ""
    echo "Kernel Settings:"
    echo "  ip_forward: $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 'N/A')"
    if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
        echo "  bridge-nf-call-iptables: $(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
        echo "  bridge-nf-call-arptables: $(cat /proc/sys/net/bridge/bridge-nf-call-arptables 2>/dev/null || echo 'N/A')"
    fi

    # DHCP leases
    echo ""
    echo "DHCP Leases (Connected Devices):"
    if [ -f /var/lib/misc/dnsmasq.leases ]; then
        LEASE_COUNT=$(wc -l < /var/lib/misc/dnsmasq.leases)
        echo "  Active leases: $LEASE_COUNT"
        if [ "$LEASE_COUNT" -gt 0 ]; then
            while read -r line; do
                MAC=$(echo "$line" | awk '{print $2}')
                IP=$(echo "$line" | awk '{print $3}')
                HOST=$(echo "$line" | awk '{print $4}')
                echo "    $IP - $MAC - ${HOST:-unknown}"
            done < /var/lib/misc/dnsmasq.leases
        fi
    else
        echo "  No lease file found"
    fi

    # ARP table
    echo ""
    echo "ARP Table (ip neigh):"
    ip neigh show dev "$BRIDGE_NAME" 2>/dev/null | head -10 || echo "  No entries"

    echo ""
    echo "============================================================"
}

# -----------------------------------------------------------------------------
# Start Bridge Mode
# -----------------------------------------------------------------------------
start_bridge() {
    print_banner
    echo ""

    log_info "Starting RAKSHAK Bridge Mode..."
    echo ""

    # Check prerequisites
    if ! check_prerequisites; then
        log_error "Cannot start bridge mode - prerequisites not met"
        exit 1
    fi
    echo ""

    # Load kernel module
    if ! load_bridge_module; then
        exit 1
    fi

    # Enable kernel settings
    if ! enable_kernel_settings; then
        exit 1
    fi

    # Create bridge
    if ! create_bridge; then
        exit 1
    fi

    # Configure dnsmasq
    if ! configure_dnsmasq; then
        log_warning "DHCP configuration failed, continuing anyway"
    fi

    # Setup NAT
    setup_nat_for_bridge

    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}     RAKSHAK BRIDGE MODE ACTIVE${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo "  Network Topology:"
    echo "  Internet -> Modem -> [$ETH_WAN] RAKSHAK [$BRIDGE_NAME] -> Router (AP) -> IoT"
    echo "                                     |"
    echo "                                 $ETH_LAN (member)"
    echo ""
    echo "  Bridge Interface: $BRIDGE_NAME"
    echo "  Bridge IP:        $BRIDGE_IP/$BRIDGE_NETMASK"
    echo "  Member Interface: $ETH_LAN"
    echo "  WAN Interface:    $ETH_WAN"
    echo "  DHCP Range:       $DHCP_RANGE_START - $DHCP_RANGE_END"
    echo ""
    echo "  Capabilities:"
    echo "    - Full Layer-2 visibility"
    echo "    - ARP traffic monitoring"
    echo "    - SSDP/ONVIF passive discovery"
    echo "    - Static IP device detection"
    echo ""
    echo -e "${GREEN}============================================================${NC}"

    log_success "RAKSHAK Bridge Mode started successfully"
}

# -----------------------------------------------------------------------------
# Stop Bridge Mode
# -----------------------------------------------------------------------------
stop_bridge() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Must run as root (use: sudo $0 --stop)"
        exit 1
    fi

    remove_bridge
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
case "$1" in
    --start)
        start_bridge
        ;;
    --stop)
        stop_bridge
        ;;
    --status)
        show_status
        ;;
    --verify)
        verify_bridge
        ;;
    --help|-h)
        print_banner
        echo "Usage: sudo $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --start         Create bridge and start bridge mode"
        echo "  --stop          Remove bridge (rollback to direct mode)"
        echo "  --status        Show bridge status"
        echo "  --verify        Verify bridge is working correctly"
        echo "  --help          Show this help"
        echo ""
        echo "Environment Variables (optional):"
        echo "  BRIDGE_NAME       Bridge interface name (default: br0)"
        echo "  ETH_LAN           LAN interface to add to bridge (default: enx207bd51a6a7d)"
        echo "  ETH_WAN           WAN interface for internet (default: wlo1)"
        echo "  BRIDGE_IP         Bridge IP address (default: 10.42.0.1)"
        echo "  BRIDGE_NETMASK    Bridge netmask bits (default: 24)"
        echo ""
        echo "Example:"
        echo "  sudo ./setup_bridge.sh --start"
        echo "  sudo ETH_LAN=eth1 ./setup_bridge.sh --start"
        echo ""
        ;;
    *)
        print_banner
        echo "Use --start to create bridge and start bridge mode"
        echo "Use --status to show current status"
        echo "Use --verify to verify bridge is working"
        echo "Use --help for more options"
        echo ""
        ;;
esac
